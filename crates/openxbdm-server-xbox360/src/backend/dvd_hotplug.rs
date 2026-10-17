//! Optical drive SATA hot-plug support (stock DMSATA, 0x91f3f078..0x91f401e8,
//! and the tray notification 0x91f3f6f0). At startup the monitor takes over
//! the interrupt routine of the CD-ROM SATA channel and the start I/O routine
//! of the CD-ROM driver, so that a drive that is plugged in again is
//! reinitialized and probed for a DVD emulator.

mod error;

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::mem::offset_of;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use core::time::Duration;

use openxbdm_core::status::KernelError;
use openxbdm_core::status::NtStatus;
use openxbdm_server::Server;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::session::debug_capture_print;
use openxbdm_server::text::Text;
use xbox360::console::hardware_flags;
use xbox360::console::kernel_version;
use xbox360::time::relative_interval;
use xbox360_sys::mmio::AtaStatus;
use xbox360_sys::mmio::SataHotplug;
use xbox360_sys::mmio::SataRegisters;
use xbox360_sys::processor::HardwareThread;
use xbox360_sys::processor::Kpcr;
use xbox360_sys::processor::current_irql;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::CdromChannelInformation;
use xbox360_sys::xboxkrnl::DebugMonitorService;
use xbox360_sys::xboxkrnl::DeviceControlParameters;
use xbox360_sys::xboxkrnl::DeviceObject;
use xbox360_sys::xboxkrnl::DeviceObjectFlags;
use xbox360_sys::xboxkrnl::DriverObject;
use xbox360_sys::xboxkrnl::HardwareFlags;
use xbox360_sys::xboxkrnl::IoControlCode;
use xbox360_sys::xboxkrnl::IoStackControl;
use xbox360_sys::xboxkrnl::IrpMajorFunction;
use xbox360_sys::xboxkrnl::Irql;
use xbox360_sys::xboxkrnl::Kdpc;
use xbox360_sys::xboxkrnl::KernelU8;
use xbox360_sys::xboxkrnl::KernelU32;
use xbox360_sys::xboxkrnl::KspinLock;
use xbox360_sys::xboxkrnl::Ktimer;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::ObjectAttributeFlags;
use xbox360_sys::xboxkrnl::ScsiInquiryData;
use xbox360_sys::xboxkrnl::ScsiPassThroughDirect;
use xbox360_sys::xboxkrnl::SmcCommand;
use xbox360_sys::xboxkrnl::SmcMessage;

use self::error::PatchError;
use super::Console;
use crate::exports::bridged;
use crate::kernel;
use crate::kernel::version_words;

xbox360_sys::import_thunk!(
    #[allow(non_snake_case)]
    DbgPrintInquiry(format: *const u8, vendor: *const u8, product: *const u8) -> u32,
    lib = xbox360_sys::lib_index::XBOXKRNL,
    ordinal = 3
);

/// Bits of the hot-plug register written back after a removal or an
/// insertion; their device meaning is unknown.
const HOTPLUG_REMOVED: SataHotplug = SataHotplug::from_bits_retain(0x10);
const HOTPLUG_INSERTED: SataHotplug = SataHotplug::from_bits_retain(0x20);

/// Channel timer ticks before a queued reinitialization starts.
const REINIT_DELAY_TICKS: u8 = 3;
const TICK_MILLISECONDS: u32 = 100;

/// Longest text of the stock trace producer (0x91f3ebb0).
const TRACE_TEXT_CAPACITY: usize = 0x1ff;

/// Trace texts that can wait for the server thread; a text is dropped
/// while every slot is taken.
const TRACE_SLOTS: usize = 16;

/// Hot-plug DPC (stock 0x91f9fdc4).
static HOTPLUG_DPC: Kdpc = Kdpc::new();
/// Request without stack locations queued to reinitialize the drive (stock
/// 0x91f9fde0).
static REINIT_IRP: AtomicU32 = AtomicU32::new(0);
/// [`HotplugState`] word.
static HOTPLUG_FLAGS: AtomicU32 = AtomicU32::new(0);
/// Reinitialization requests queued and not yet started (stock 0x91f9fde8).
static QUEUED: AtomicI32 = AtomicI32::new(0);
/// Inquiries requested and not yet completed (stock 0x91f9fdf0).
static INQUIRIES: AtomicI32 = AtomicI32::new(0);
static INQUIRY: KernelStorage<Inquiry> = KernelStorage::new(Inquiry {
    request: ScsiPassThroughDirect::new(),
    data: ScsiInquiryData::new(),
});
/// Request of the inquiry (stock 0x91f9fe78).
static INQUIRY_IRP: AtomicU32 = AtomicU32::new(0);
/// Copy of the CD-ROM driver object with the start I/O hook (stock
/// 0x91f9fe7c).
static DRIVER_OBJECT: KernelStorage<DriverObject> =
    KernelStorage::new(DriverObject::new(None, [None; 11]));
/// CD-ROM channel extension (stock 0x91f9feb4); set by `find_channel`
/// before any hook is installed.
static CHANNEL: AtomicU32 = AtomicU32::new(0);
/// Channel packet routines from the debug monitor service; 0 when the
/// kernel gives none and the I/O manager routines apply (stock 0x91f9fec0,
/// 0x91f9fec4).
static START_PACKET: AtomicU32 = AtomicU32::new(0);
static START_NEXT_PACKET: AtomicU32 = AtomicU32::new(0);
/// [`EmulatorState`] word.
static DVD_EMULATOR_STATE: AtomicU32 = AtomicU32::new(0);
/// A reinitialization finished; the server thread completes it (stock
/// 0x91facf3c).
static DRIVE_REINITIALIZED: AtomicBool = AtomicBool::new(false);
/// SMC notification registration (stock 0x91f97454).
static TRAY_REGISTRATION: NotificationRegistration = NotificationRegistration::new();
static TRACE: TraceQueue = TraceQueue {
    lock: KspinLock::new(),
    ring: UnsafeCell::new(TraceRing {
        traces: [Trace::UpdatingDriver; TRACE_SLOTS],
        first: 0,
        count: 0,
    }),
};

/// The kernel's channel extension of the CD-ROM SATA channel. The kernel's
/// interrupt routine, DPCs and timer use it concurrently, so every field is
/// atomic or a kernel object. The kernel acts on the `KernelU32` and
/// `KernelU8` fields, so stores to them are unsafe.
#[repr(C)]
struct ChannelExtension {
    /// Address of the SATA registers (`Operational` in the stock texts).
    registers: KernelU32,
    /// Routine `(channel, irp)` that starts a request on the channel.
    start_io: KernelU32,
    /// Routine `(channel, registers, status) -> BOOLEAN` the interrupt runs.
    interrupt_routine: KernelU32,
    /// Routine `(channel, irp, status)` the channel DPC runs.
    completion_routine: KernelU32,
    reset_routine: KernelU32,
    /// Routine `(channel)` the channel timer runs once its tick count expires.
    wait_routine: KernelU32,
    timer: Ktimer,
    timer_dpc: Kdpc,
    dpc: ChannelDpc,
    _reserved_78: [AtomicU32; 4],
    /// Cleared by the reinitialization; purpose unknown.
    unknown_88: KernelU32,
    /// Cleared by the reinitialization; purpose unknown.
    unknown_8c: KernelU32,
    /// Interrupt service routine slot; the kernel passes its address to the
    /// routine.
    interrupt: KernelU32,
    _reserved_94: AtomicU32,
    lock: KspinLock,
    _reserved_9c: [AtomicU8; 5],
    irql: KernelU8,
    _reserved_a2: [AtomicU8; 2],
    /// PRCB address of the processor that holds `lock`.
    lock_owner: AtomicU32,
    /// Cleared by the reinitialization; purpose unknown.
    unknown_a8: KernelU8,
    /// Channel timer ticks before the wait routine runs.
    wait_ticks: KernelU8,
    /// Set to 0 by the start I/O hook; purpose unknown.
    unknown_aa: KernelU8,
    /// Set to 4 by the start I/O hook; purpose unknown.
    unknown_ab: KernelU8,
    /// A request the start I/O hook only marks as started.
    held_irp: KernelU32,
    _reserved_b0: [AtomicU8; 0x21],
    held_irp_started: KernelU8,
}

impl ChannelExtension {
    /// # Safety
    ///
    /// `address` must be the kernel's channel extension of a SATA channel:
    /// aligned to 8, at least `size_of::<Self>()` (0xd8) bytes, and
    /// allocated while the system runs.
    unsafe fn at(address: u32) -> &'static Self {
        // SAFETY: guaranteed by the caller.
        unsafe { &*core::ptr::with_exposed_provenance(address as usize) }
    }

    fn address(&self) -> u32 {
        core::ptr::from_ref(self).expose_provenance() as u32
    }

    fn device(&self) -> Device {
        // SAFETY: the channel's device object is never deleted.
        unsafe { Device::from_address(self.dpc.device.load(Ordering::Relaxed)) }
    }

    fn irql(&self) -> Irql {
        Irql::new(self.irql.load(Ordering::Relaxed))
    }

    /// Take the channel lock at the channel IRQL from `expected` IRQL.
    fn lock(&self, expected: Irql) -> ChannelLock<'_> {
        check(current_irql() == expected);

        // SAFETY: `lock` is the spin lock of the kernel's channel extension.
        unsafe {
            xboxkrnl::KfRaiseIrql(self.irql());
            xboxkrnl::KeAcquireSpinLockAtRaisedIrql(self.lock.as_ptr());
        }
        self.lock_owner.store(prcb(), Ordering::Relaxed);

        ChannelLock(self)
    }
}

/// The `KDPC` of the channel. Word 4, the deferred context in Xenia's
/// layout, holds the channel's device object.
#[repr(C)]
struct ChannelDpc {
    _header: [AtomicU32; 4],
    device: KernelU32,
    _arguments: [AtomicU32; 2],
}

const _: () = {
    assert!(size_of::<ChannelDpc>() == size_of::<Kdpc>());
    assert!(offset_of!(ChannelExtension, timer) == 0x18);
    assert!(offset_of!(ChannelExtension, timer_dpc) == 0x40);
    assert!(offset_of!(ChannelExtension, dpc) == 0x5c);
    assert!(offset_of!(ChannelExtension, dpc) + offset_of!(ChannelDpc, device) == 0x6c);
    assert!(offset_of!(ChannelExtension, unknown_88) == 0x88);
    assert!(offset_of!(ChannelExtension, interrupt) == 0x90);
    assert!(offset_of!(ChannelExtension, lock) == 0x98);
    assert!(offset_of!(ChannelExtension, irql) == 0xa1);
    assert!(offset_of!(ChannelExtension, lock_owner) == 0xa4);
    assert!(offset_of!(ChannelExtension, unknown_a8) == 0xa8);
    assert!(offset_of!(ChannelExtension, unknown_ab) == 0xab);
    assert!(offset_of!(ChannelExtension, held_irp) == 0xac);
    assert!(offset_of!(ChannelExtension, held_irp_started) == 0xd1);
    assert!(size_of::<ChannelExtension>() == 0xd8);
    assert!(align_of::<ChannelExtension>() == 8);
};

struct ChannelLock<'a>(&'a ChannelExtension);

impl ChannelLock<'_> {
    fn release(self, irql: Irql) {
        let channel = self.0;

        check(current_irql() == channel.irql());
        check(channel.lock_owner.load(Ordering::Relaxed) == prcb());

        // SAFETY: this processor holds the channel lock, as checked above.
        unsafe {
            xboxkrnl::KeReleaseSpinLockFromRaisedIrql(channel.lock.as_ptr());
            xboxkrnl::KfLowerIrql(irql);
        }
    }
}

/// An ATA command without data.
struct AtaCommand {
    features: u8,
    sector_count: u8,
    command: u8,
}

impl AtaCommand {
    /// SET FEATURES (0xef), subcommand 3 (set transfer mode) to 0x42 (Ultra
    /// DMA mode 2): reinitializes the drive.
    const REINITIALIZE: Self = Self {
        features: 3,
        sector_count: 0x42,
        command: 0xef,
    };
}

xbox360_sys::flags! {
    /// Optical drive emulator state (stock 0x91f9fec8).
    pub struct EmulatorState(u32) {
        RUNNING = 0x1,
        /// The emulator reported revision `0002`.
        REVISION_0002 = 0x2,
        /// The emulator reported media type 1.
        MEDIA_TYPE_1 = 0x4,
    }
}

xbox360_sys::flags! {
    /// Hot-plug progress (stock 0x91f9fde4).
    pub struct HotplugState(u32) {
        /// A hot-plug event waits for the DPC.
        EVENT_PENDING = 0x1,
        /// A reinitialization runs.
        REINITIALIZING = 0x2,
    }
}

/// Tray state of an [`SmcCommand::TrayState`] message.
#[derive(Clone, Copy)]
enum TrayState {
    Open,
    OpenRequest,
    Close,
    Opening,
    Closing,
    Unknown,
    Spinup,
}

impl TrayState {
    /// Byte 1 of the message is this plus the state.
    const BASE: u8 = 0x60;

    fn from_message(byte: u8) -> Option<Self> {
        Some(match byte.wrapping_sub(Self::BASE) {
            0 => Self::Open,
            1 => Self::OpenRequest,
            2 => Self::Close,
            3 => Self::Opening,
            4 => Self::Closing,
            5 => Self::Unknown,
            6 => Self::Spinup,
            _ => return None,
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::Open => "TRAY_OPEN",
            Self::OpenRequest => "TRAY_OPEN_REQUEST",
            Self::Close => "TRAY_CLOSE",
            Self::Opening => "TRAY_OPENING",
            Self::Closing => "TRAY_CLOSING",
            Self::Unknown => "TRAY_UNKNOWN",
            Self::Spinup => "TRAY_SPINUP",
        }
    }
}

/// Kernel-owned storage in static memory.
#[repr(C, align(8))]
struct KernelStorage<T>(UnsafeCell<T>);

// SAFETY: the kernel or the hot-plug protocol serializes every access.
unsafe impl<T> Sync for KernelStorage<T> {}

impl<T> KernelStorage<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// Request and data of the inquiry after a reinitialization (stock
/// 0x91f9fdf4 and 0x91f9fe18).
#[repr(C)]
struct Inquiry {
    request: ScsiPassThroughDirect,
    data: ScsiInquiryData,
}

/// A text of the stock trace producer (0x91f3ebb0) with the values it
/// prints. The server thread formats it, so the producer, which may run
/// above dispatch level, stores only the values.
#[derive(Clone, Copy)]
enum Trace {
    UpdatingDriver,
    UpdatedChannelIsr,
    Patched {
        build: u16,
    },
    KernelVersion([u16; 4]),
    ChannelNotFound,
    ChannelExtension(u32),
    ChannelOperational(u32),
    CdromOperational,
    ChannelDevice(u32),
    CdromDevice(u32),
    InvalidChannel,
    PlugIn {
        processor: u8,
    },
    CancellingWait {
        reinitializing: bool,
    },
    CancellingReset,
    CancellingRequest,
    QueueReinit {
        queued: i32,
    },
    AbortPending {
        irp: u32,
    },
    StartIo {
        processor: u8,
        hotplug: u32,
        queued: i32,
        irp: u32,
    },
    StartReinit,
    SkipReinit {
        remaining: i32,
    },
    HotplugAbort {
        irp: u32,
    },
    ReinitDelay {
        processor: u8,
    },
    StartReinitialize {
        processor: u8,
        irp: u32,
    },
    DeviceBusy {
        sstatus: u32,
        scontrol: u32,
        serror: u32,
        status: u8,
    },
    FinishReinitialize {
        processor: u8,
        irp: u32,
    },
    ReinitTimedOut,
    Tray {
        state: TrayState,
    },
}

impl Trace {
    /// The text, cut as the producer cuts it.
    #[allow(
        clippy::write_with_newline,
        reason = "the format strings are the stock texts verbatim"
    )]
    fn write(self, text: &mut Text<TRACE_TEXT_CAPACITY>) {
        let _ = match self {
            Self::UpdatingDriver => text.write_str("XBDM: Updating CD-ROM driver.\n"),
            Self::UpdatedChannelIsr => text.write_str("XBDM: Updated Channel ISR.\n"),
            Self::Patched { build } => write!(
                text,
                "XBDM: Patched CD-ROM driver for Kernel (ver={build:04})\n"
            ),
            Self::KernelVersion([major, minor, build, qfe]) => write!(
                text,
                "XBDM: DmSataFindCdromChannelObject - KernelVer ({major}.{minor}.{build}.{qfe:x})\n"
            ),
            Self::ChannelNotFound => {
                text.write_str("XBDM: DmSataFindCdromChannelObject - Did not find Channel\n")
            }
            Self::ChannelExtension(channel) => {
                write!(text, "XBDM:  ChannelExtension ({channel:08x})\n")
            }
            Self::ChannelOperational(registers) => write!(
                text,
                "XBDM:  ChannelExtension->Operational ({registers:08x})\n"
            ),
            Self::CdromOperational => {
                const _: () = assert!(SataRegisters::CDROM_ADDRESS == 0x7fea_1200);
                text.write_str("XBDM:  SataCdromOperational (7fea1200)\n")
            }
            Self::ChannelDevice(device) => write!(
                text,
                "XBDM:  ChannelExtension==>DeviceObject ({device:08x})\n"
            ),
            Self::CdromDevice(device) => {
                write!(text, "XBDM:  SataCdromDeviceObject ({device:08x})\n")
            }
            Self::InvalidChannel => {
                text.write_str("XBDM: DmSataFindCdromChannelObject - Invalid channel address.\n")
            }
            Self::PlugIn { processor } => {
                write!(text, "DMSATA: HotplugDPC - ({processor}) Plug In event\n")
            }
            Self::CancellingWait { reinitializing } => write!(
                text,
                "DMSATA: HotplugDPC - Cancelling Wait (Re-init={})\n",
                u32::from(reinitializing)
            ),
            Self::CancellingReset => text.write_str("DMSATA: HotplugDPC - Cancelling RESET\n"),
            Self::CancellingRequest => {
                text.write_str("DMSATA: HotplugDPC - Cancelling current request\n")
            }
            Self::QueueReinit { queued } => {
                write!(text, "DMSATA: Queue Re-Init IRP (count={queued})\n")
            }
            Self::AbortPending { irp } => {
                write!(
                    text,
                    "DMSATA: HotplugDPC - Abort Pending IRP (IRP={irp:x})\n"
                )
            }
            Self::StartIo {
                processor,
                hotplug,
                queued,
                irp,
            } => write!(
                text,
                "DMSATA: DmSataCdRomStartIo - ({processor}) (Hotplug={hotplug:x}, Queued={queued}, Irp={irp:x})\n"
            ),
            Self::StartReinit => text.write_str("DMSATA: Start Re-Init\n"),
            Self::SkipReinit { remaining } => {
                write!(text, "DMSATA: Skip re-init (Count={remaining})\n")
            }
            Self::HotplugAbort { irp } => {
                write!(text, "DMSATA: Hotplug/Pre-Init Aborting IRP ({irp:x})\n")
            }
            Self::ReinitDelay { processor } => {
                const _: () = assert!(REINIT_DELAY_TICKS as u32 * TICK_MILLISECONDS == 300);
                write!(
                    text,
                    "DMSATA: Start re-init request in 300 ms ({processor})\n"
                )
            }
            Self::StartReinitialize { processor, irp } => write!(
                text,
                "DMSATA: StartReinitialize ({processor}) (Irp={irp:08x})\n"
            ),
            Self::DeviceBusy {
                sstatus,
                scontrol,
                serror,
                status,
            } => write!(
                text,
                "DMSATA: StartReinitialize - Device busy\n  SStatus = {sstatus:08x}\n  SControl = {scontrol:08x}\n  SError = {serror:08x}\n  DevStatus = {status:02x}\n"
            ),
            Self::FinishReinitialize { processor, irp } => write!(
                text,
                "DMSATA: FinishReinitialize ({processor}) (Irp={irp:08x})\n"
            ),
            Self::ReinitTimedOut => {
                text.write_str("DMSATA: Re-init command timed out.  Disable \\device\\cdrom0\n")
            }
            Self::Tray { state } => {
                write!(text, "[XBDM] Tray notification - {}\n", state.name())
            }
        };
    }
}

/// Traces waiting for the server thread, which appends their texts to the
/// debug capture ring.
struct TraceQueue {
    lock: KspinLock,
    ring: UnsafeCell<TraceRing>,
}

// SAFETY: every access to `ring` holds the spin lock.
unsafe impl Sync for TraceQueue {}

impl TraceQueue {
    /// Queue `trace`; it is dropped when the queue is full. Above dispatch
    /// level the producer may have interrupted the lock holder, so it only
    /// tries the lock.
    fn push(&self, trace: Trace) {
        let lock = self.lock.as_ptr();
        let irql = current_irql();

        // SAFETY: `lock` is the queue's spin lock, which starts released.
        let previous = unsafe {
            if irql < Irql::DISPATCH {
                Some(xboxkrnl::KfAcquireSpinLock(lock))
            } else if irql == Irql::DISPATCH {
                xboxkrnl::KeAcquireSpinLockAtRaisedIrql(lock);
                None
            } else if xboxkrnl::KeTryToAcquireSpinLockAtRaisedIrql(lock).get() {
                None
            } else {
                return;
            }
        };

        // SAFETY: the spin lock is held.
        let ring = unsafe { &mut *self.ring.get() };
        if ring.count < TRACE_SLOTS {
            ring.traces[(ring.first + ring.count) % TRACE_SLOTS] = trace;
            ring.count += 1;
        }

        // SAFETY: this thread holds `lock`, taken above in the mode `previous` records.
        unsafe {
            match previous {
                Some(previous) => xboxkrnl::KfReleaseSpinLock(lock, previous),
                None => xboxkrnl::KeReleaseSpinLockFromRaisedIrql(lock),
            }
        };
    }

    /// Take the oldest trace; called on the server thread.
    fn pop(&self) -> Option<Trace> {
        let lock = self.lock.as_ptr();

        // SAFETY: `lock` is the queue's spin lock.
        let previous = unsafe { xboxkrnl::KfAcquireSpinLock(lock) };

        // SAFETY: the spin lock is held.
        let ring = unsafe { &mut *self.ring.get() };
        let trace = (ring.count != 0).then(|| {
            let trace = ring.traces[ring.first];
            ring.first = (ring.first + 1) % TRACE_SLOTS;
            ring.count -= 1;
            trace
        });

        // SAFETY: this thread acquired `lock` above.
        unsafe { xboxkrnl::KfReleaseSpinLock(lock, previous) };

        trace
    }
}

struct TraceRing {
    traces: [Trace; TRACE_SLOTS],
    first: usize,
    count: usize,
}

/// A kernel device object that stays allocated while the system runs.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Device(u32);

impl Device {
    /// # Safety
    ///
    /// `object` must be the address of a device object that is never
    /// deleted.
    unsafe fn from_address(object: u32) -> Self {
        Self(object)
    }

    fn as_ptr(self) -> *mut DeviceObject {
        core::ptr::with_exposed_provenance_mut(self.0 as usize)
    }

    /// The request the device is processing; the I/O manager changes it.
    fn current_irp(self) -> u32 {
        // SAFETY: the device object is live (type invariant); the field is
        // an aligned pointer word.
        unsafe { AtomicPtr::from_ptr(&raw mut (*self.as_ptr()).current_irp) }
            .load(Ordering::Relaxed)
            .expose_provenance() as u32
    }

    /// The [`DeviceObjectFlags`] word, which the kernel also changes.
    fn flags(self) -> &'static KernelU32 {
        // SAFETY: as in `current_irp`; the flags are a transparent word and
        // `KernelU32` a transparent atomic word.
        unsafe { &*(&raw const (*self.as_ptr()).flags).cast::<KernelU32>() }
    }

    /// Address of the driver object.
    fn driver_object(self) -> &'static KernelU32 {
        // SAFETY: as in `flags`; the field is a pointer word.
        unsafe { &*(&raw const (*self.as_ptr()).driver_object).cast::<KernelU32>() }
    }

    fn stack_size(self) -> u8 {
        // SAFETY: as in `current_irp`; the kernel sets the byte at creation.
        unsafe { (*self.as_ptr()).stack_size }
    }
}

/// A live I/O request.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Irp(u32);

impl Irp {
    /// # Safety
    ///
    /// A nonzero `irp` must be the address of a request that stays live
    /// while the value is used.
    unsafe fn new(irp: u32) -> Option<Self> {
        (irp != 0).then_some(Self(irp))
    }

    fn as_ptr(self) -> *mut xboxkrnl::Irp {
        core::ptr::with_exposed_provenance_mut(self.0 as usize)
    }
}

/// Stock trace producer 0x91f3ebb0.
fn trace(trace: Trace) {
    TRACE.push(trace);
}

fn processor() -> u8 {
    Kpcr::current().processor_number().get()
}

/// Address of this processor's PRCB, which the channel lock records as its
/// owner.
fn prcb() -> u32 {
    core::ptr::from_ref(&Kpcr::current().prcb).addr() as u32
}

/// Stock assertion: the trap the debug routine or the kernel handles.
fn check(condition: bool) {
    if !condition {
        // SAFETY: raises the trap exception stock raises.
        unsafe { core::arch::asm!("twi 31, 0, 0x19") };
    }
}

/// The reinitialization request; `initialize` allocates it before any hook
/// is installed, and it is never freed.
fn reinit_irp() -> Irp {
    Irp(REINIT_IRP.load(Ordering::Relaxed))
}

/// The channel `find_channel` validated.
fn channel() -> &'static ChannelExtension {
    // SAFETY: `find_channel` stores the validated extension before the
    // hooks that call this are installed.
    unsafe { ChannelExtension::at(CHANNEL.load(Ordering::Relaxed)) }
}

/// A routine address the kernel provides; 0 means none.
fn routine(address: u32) -> Option<u32> {
    (address != 0).then_some(address)
}

fn start_packet(channel: &ChannelExtension, irp: Irp) {
    match routine(START_PACKET.load(Ordering::Relaxed)) {
        // SAFETY: the kernel gave a routine taking (channel, irp).
        Some(routine) => {
            unsafe { kernel::call_export(routine, channel.address(), irp.0, 0, 0) };
        }
        // SAFETY: the device and request are the channel's live kernel objects.
        None => unsafe {
            xboxkrnl::IoStartPacket(channel.device().as_ptr(), irp.as_ptr(), core::ptr::null())
        },
    }
}

fn start_next_packet(channel: &ChannelExtension) {
    match routine(START_NEXT_PACKET.load(Ordering::Relaxed)) {
        // SAFETY: the kernel gave a routine taking (channel).
        Some(routine) => {
            unsafe { kernel::call_export(routine, channel.address(), 0, 0, 0) };
        }
        // SAFETY: the device is the channel's live kernel device object.
        None => unsafe { xboxkrnl::IoStartNextPacket(channel.device().as_ptr()) },
    }
}

fn start_channel_timer(channel: &ChannelExtension, due: i64, period_ms: u32) {
    // SAFETY: the timer and its DPC are initialized objects inside the
    // kernel's channel extension.
    unsafe {
        xboxkrnl::KeSetTimerEx(
            channel.timer.as_ptr(),
            due,
            period_ms,
            channel.timer_dpc.as_ptr(),
        )
    };
}

/// SCSI INQUIRY of a [`ScsiInquiryData`] into `buffer`.
fn inquiry_request(buffer: u32) -> ScsiPassThroughDirect {
    const OPERATION_INQUIRY: u8 = 0x12;
    /// Control byte of the command; stock sets the vendor-specific bits.
    const CONTROL: u8 = 0xc0;
    const LENGTH: u8 = size_of::<ScsiInquiryData>() as u8;

    let mut request = ScsiPassThroughDirect::new();
    request.length = size_of::<ScsiPassThroughDirect>() as u16;
    // Stock stores 1; meaning unknown.
    request.unknown_07 = 1;
    request.data_transfer_length = u32::from(LENGTH);
    request.data_buffer = buffer;
    request.cdb[0] = OPERATION_INQUIRY;
    request.cdb[4] = LENGTH;
    request.cdb[5] = CONTROL;

    request
}

bridged!(tray_notification_entry, tray_notification);
bridged!(start_io_hook_entry, start_io_hook);
bridged!(interrupt_hook_entry, interrupt_hook);
bridged!(start_reinitialize_entry, start_reinitialize);
bridged!(reinit_interrupt_entry, reinit_interrupt);
bridged!(finish_reinitialize_entry, finish_reinitialize);
bridged!(inquiry_completion_entry, inquiry_completion);
bridged!(hotplug_dpc_entry, hotplug_dpc);

/// Startup steps of stock module initialization 0x91f32b10..0x91f32ba8:
/// register the tray notification, reference `\Device\Cdrom0` (never
/// released) and patch its driver.
pub(crate) fn install(trace_mask: TraceMask) {
    // SAFETY: the record is not registered yet. The routine stays loaded
    // while the module runs.
    unsafe {
        TRAY_REGISTRATION.routine.store(
            tray_notification_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
        TRAY_REGISTRATION.priority.store(1, Ordering::Relaxed);
        xboxkrnl::HalRegisterSMCNotification(TRAY_REGISTRATION.as_ptr(), true);
    }

    let verbose = trace_mask.contains(TraceMask::CDROM);
    let name = kernel::ansi_string(b"\\Device\\Cdrom0");

    let mut object = 0u32;
    // SAFETY: `name` refers to a static string and `object` is a local word.
    let found = unsafe {
        xboxkrnl::ObReferenceObjectByName(&name, ObjectAttributeFlags::empty(), 0, 0, &mut object)
    }
    .result();
    if (found.is_err() || object == 0) && verbose {
        kernel::debug_print(c"[xbdm] Failed to find object: CdRom0.\n");
    }

    // SAFETY: a nonzero `object` is the referenced device, whose reference
    // is never released.
    let device = (object != 0).then(|| unsafe { Device::from_address(object) });
    if patch(device).is_err() && verbose {
        kernel::debug_print(c"[xbdm] Failed to update CdRom0.\n");
    }
}

/// Patch the CD-ROM driver (0x91f40088).
fn patch(device: Option<Device>) -> Result<(), PatchError> {
    let device = device.ok_or(PatchError::NoDevice)?;

    trace(Trace::UpdatingDriver);
    let version = kernel_version();
    let channel = find_channel(device, version_words(version))?;
    initialize(device)?;

    let driver_object = device.driver_object();
    let driver = core::ptr::with_exposed_provenance::<DriverObject>(
        driver_object.load(Ordering::Relaxed) as usize,
    );
    if driver.is_null() {
        return Err(PatchError::NoDriverObject);
    }

    // SAFETY: released below after the driver object is replaced.
    let irql = unsafe { xboxkrnl::IoAcquireDeviceObjectLock() };
    let driver_copy = DRIVER_OBJECT.get();
    // SAFETY: `driver` is the device's driver object; the copy is unused
    // until the device points at it below. The hook entry runs
    // `start_io_hook`, which takes (device, irp) in the console ABI.
    unsafe {
        core::ptr::copy_nonoverlapping(driver, driver_copy, 1);
        (*driver_copy).start_io = Some(core::mem::transmute::<
            unsafe extern "C" fn(),
            xboxkrnl::DriverStartIo,
        >(start_io_hook_entry));
    }
    // SAFETY: the copy is the device's driver object with the start I/O
    // routine replaced, and stays in static storage.
    unsafe { driver_object.store(driver_copy.expose_provenance() as u32, Ordering::Relaxed) };
    // SAFETY: `irql` is the result of the acquisition above.
    unsafe { xboxkrnl::IoReleaseDeviceObjectLock(irql) };

    let lock = channel.lock(Irql::PASSIVE);
    // SAFETY: the hook entry runs `interrupt_hook`, which takes the
    // interrupt slot and the registers as the kernel passes them; the
    // channel lock is held, as stock holds it.
    unsafe {
        channel.interrupt.store(
            interrupt_hook_entry as *const () as usize as u32,
            Ordering::Relaxed,
        )
    };
    lock.release(Irql::PASSIVE);
    trace(Trace::UpdatedChannelIsr);

    detect_dvd_emulator(device);
    trace(Trace::Patched {
        build: version.build,
    });

    Ok(())
}

/// Locate the channel extension of the CD-ROM (0x91f3f518,
/// `DmSataFindCdromChannelObject`).
fn find_channel(
    device: Device,
    version: [u16; 4],
) -> Result<&'static ChannelExtension, PatchError> {
    let [major, minor, build, qfe] = version;
    trace(Trace::KernelVersion(version));
    if major != 2 || minor != 0 || qfe != 0x8000 {
        return Err(PatchError::UnsupportedKernel);
    }

    let address = match build {
        0x760 => 0x8013_7a00,
        0x8c1 | 0x8cf | 0x8d2 => 0x8013_7b20,
        0x973 | 0x974 => 0x8012_76c0,
        _ => {
            let mut info = CdromChannelInformation::default();
            // SAFETY: `info` is a local buffer of the size passed.
            let status = unsafe {
                xboxkrnl::ExDebugMonitorService(
                    DebugMonitorService::CdromChannel,
                    1,
                    size_of::<CdromChannelInformation>() as u32,
                    (&raw mut info).expose_provenance() as u32,
                )
            };

            let reported = status.is_success().then(|| {
                START_PACKET.store(info.start_packet, Ordering::Relaxed);
                START_NEXT_PACKET.store(info.start_next_packet, Ordering::Relaxed);
                info.channel
            });
            let Some(channel) = reported.filter(|&channel| channel != 0) else {
                trace(Trace::ChannelNotFound);
                return Err(PatchError::ChannelNotFound);
            };

            channel
        }
    };

    // SAFETY: the address is the kernel's static CD-ROM channel extension of
    // this build, or the one the debug monitor service reported.
    let channel = unsafe { ChannelExtension::at(address) };
    let registers = channel.registers.load(Ordering::Relaxed);
    let channel_device = channel.dpc.device.load(Ordering::Relaxed);
    if registers as usize == SataRegisters::CDROM_ADDRESS && channel_device == device.0 {
        CHANNEL.store(address, Ordering::Relaxed);
        return Ok(channel);
    }

    trace(Trace::ChannelExtension(address));
    trace(Trace::ChannelOperational(registers));
    trace(Trace::CdromOperational);
    trace(Trace::ChannelDevice(channel_device));
    trace(Trace::CdromDevice(device.0));
    trace(Trace::InvalidChannel);

    Err(PatchError::InvalidChannel)
}

/// Prepare the hot-plug DPC and the two requests (0x91f3f498). The state
/// starts zeroed, as stock clears it here.
fn initialize(device: Device) -> Result<(), PatchError> {
    /// Hardware thread that runs the hot-plug DPC.
    const DPC_PROCESSOR: HardwareThread = HardwareThread::new(2).unwrap();

    let dpc = HOTPLUG_DPC.as_ptr();
    // SAFETY: HOTPLUG_DPC is static DPC storage.
    unsafe {
        xboxkrnl::KeInitializeDpc(
            dpc,
            hotplug_dpc_entry as *const () as usize,
            device.0 as usize,
        )
    };
    // SAFETY: the DPC is initialized and not queued yet; the hook that
    // queues it is installed later.
    unsafe { HOTPLUG_DPC.set_target_processor(Some(DPC_PROCESSOR)) };

    // SAFETY: IoAllocateIrp takes only a stack location count; the requests
    // it returns are never freed.
    let (reinit, inquiry) = unsafe {
        (
            Irp::new(xboxkrnl::IoAllocateIrp(0).expose_provenance() as u32),
            Irp::new(
                xboxkrnl::IoAllocateIrp(u32::from(device.stack_size())).expose_provenance() as u32,
            ),
        )
    };
    let (Some(reinit), Some(inquiry)) = (reinit, inquiry) else {
        return Err(PatchError::NoIrp);
    };

    REINIT_IRP.store(reinit.0, Ordering::Relaxed);
    INQUIRY_IRP.store(inquiry.0, Ordering::Relaxed);

    Ok(())
}

/// Channel interrupt service routine (0x91f3f3d0). A hot-plug event goes
/// to the hot-plug DPC; any other interrupt to the channel's interrupt
/// routine.
extern "C" fn interrupt_hook(interrupt: u32, registers: u32) -> u32 {
    // SAFETY: the kernel passes the address of the interrupt slot of the
    // channel extension that `patch` hooked.
    let channel =
        unsafe { ChannelExtension::at(interrupt - offset_of!(ChannelExtension, interrupt) as u32) };
    check(registers as usize == SataRegisters::CDROM_ADDRESS);

    let sata = SataRegisters::cdrom();
    let device_status = sata.status();
    let hotplug = sata.hotplug();
    if hotplug.contains(SataHotplug::INTERRUPT)
        && hotplug.intersects(SataHotplug::INSERTION.union(SataHotplug::REMOVAL))
    {
        // SAFETY: the hot-plug register makes the device write no memory.
        unsafe { sata.write_hotplug(hotplug.difference(HOTPLUG_REMOVED.union(HOTPLUG_INSERTED))) };
        HOTPLUG_FLAGS.fetch_or(HotplugState::EVENT_PENDING.bits(), Ordering::SeqCst);

        // SAFETY: HOTPLUG_DPC was initialized by `initialize` before the hook
        // was installed.
        return unsafe {
            xboxkrnl::KeInsertQueueDpc(HOTPLUG_DPC.as_ptr(), channel.address(), hotplug.bits())
        }
        .0;
    }

    match routine(channel.interrupt_routine.load(Ordering::Relaxed)) {
        // SAFETY: the channel's interrupt routine takes (channel,
        // registers, status).
        Some(routine) => unsafe {
            kernel::call_export(
                routine,
                channel.address(),
                registers,
                u32::from(device_status.bits()),
                0,
            )
        },
        // Stock returns the channel address, still in r3, as the result.
        None => channel.address(),
    }
}

/// Hot-plug DPC (0x91f3f180): acknowledge a removal, or cancel the
/// channel's work and queue a reinitialization after an insertion.
extern "C" fn hotplug_dpc(_dpc: u32, device: u32, channel: u32, hotplug: u32) {
    // SAFETY: the interrupt hook queues the DPC with the channel extension,
    // and `initialize` gave it the channel's device as its context.
    let (channel, device) =
        unsafe { (ChannelExtension::at(channel), Device::from_address(device)) };

    let hotplug = SataHotplug::from_bits_retain(hotplug);
    let acknowledge = hotplug.difference(HOTPLUG_REMOVED.union(HOTPLUG_INSERTED));
    let acknowledge = if hotplug.contains(SataHotplug::REMOVAL) {
        acknowledge.union(HOTPLUG_REMOVED)
    } else {
        trace(Trace::PlugIn {
            processor: processor(),
        });
        queue_reinitialize(device, channel);
        acknowledge.union(HOTPLUG_INSERTED)
    };

    // Deviation: stock reloads the register address from the channel
    // extension (`registers`). `find_channel` checked that it is
    // `SataRegisters::CDROM_ADDRESS`, so the constant replaces the load.
    // SAFETY: the hot-plug register makes the device write no memory.
    unsafe { SataRegisters::cdrom().write_hotplug(acknowledge) };
}

fn queue_reinitialize(device: Device, channel: &ChannelExtension) {
    const HOTPLUG_TIMER_PERIOD_MS: u32 = 1000;

    let lock = channel.lock(Irql::DISPATCH);
    let wait_routine = channel.wait_routine.load(Ordering::Relaxed);
    let reset_routine = channel.reset_routine.load(Ordering::Relaxed);
    let interrupt_routine = channel.interrupt_routine.load(Ordering::Relaxed);
    let current_irp = device.current_irp();
    let restart_timer = wait_routine != 0 || reset_routine != 0;
    let abort_current = wait_routine != 0 || interrupt_routine != 0;

    if wait_routine != 0 {
        let reinitializing = current_irp == reinit_irp().0;
        trace(Trace::CancellingWait { reinitializing });
        // SAFETY: 0 is no routine; the channel lock is held.
        unsafe { channel.wait_routine.store(0, Ordering::Relaxed) };
    }
    if reset_routine != 0 {
        trace(Trace::CancellingReset);
        // SAFETY: as above.
        unsafe { channel.reset_routine.store(0, Ordering::Relaxed) };
    }
    if interrupt_routine != 0 {
        trace(Trace::CancellingRequest);
        // SAFETY: as above.
        unsafe { channel.interrupt_routine.store(0, Ordering::Relaxed) };
    }

    QUEUED.fetch_add(1, Ordering::SeqCst);
    HOTPLUG_FLAGS.fetch_and(!HotplugState::EVENT_PENDING.bits(), Ordering::SeqCst);
    check(channel.interrupt_routine.load(Ordering::Relaxed) == 0);
    check(channel.wait_routine.load(Ordering::Relaxed) == 0);
    check(channel.reset_routine.load(Ordering::Relaxed) == 0);
    lock.release(Irql::DISPATCH);

    if restart_timer {
        start_channel_timer(
            channel,
            relative_interval(Duration::from_millis(HOTPLUG_TIMER_PERIOD_MS as u64)),
            HOTPLUG_TIMER_PERIOD_MS,
        );
    }

    trace(Trace::QueueReinit {
        queued: QUEUED.load(Ordering::SeqCst),
    });
    start_packet(channel, reinit_irp());

    if abort_current {
        trace(Trace::AbortPending { irp: current_irp });
        // SAFETY: a nonzero `current_irp` is the device's live current request.
        fail_request(channel, unsafe { Irp::new(current_irp) });
    }
}

/// Complete `irp` as removed, unless it is the reinitialization request,
/// and start the next request (0x91f3f0d8).
fn fail_request(channel: &ChannelExtension, irp: Option<Irp>) {
    check(irp.is_some());
    check(current_irql() == Irql::DISPATCH);

    if let Some(irp) = irp
        && irp != reinit_irp()
    {
        // SAFETY: `irp` is a live request the channel owns.
        unsafe {
            (*irp.as_ptr()).io_status.status = KernelError::DeviceRemoved.status();
            xboxkrnl::IoCompleteRequest(irp.as_ptr(), 0);
        }
    }

    start_next_packet(channel);
}

/// Start I/O routine of the driver object copy (0x91f3ff10,
/// `DmSataCdRomStartIo`).
extern "C" fn start_io_hook(_device: u32, irp: u32) {
    /// Hardware flag under which the monitor fails every optical drive
    /// request. Its kernel meaning is not known.
    const FAIL_OPTICAL_REQUESTS: HardwareFlags = HardwareFlags::from_bits_retain(0x4000);

    let channel = channel();
    if irp == channel.held_irp.load(Ordering::Relaxed) {
        // SAFETY: a full memory barrier, as stock issues before the store.
        unsafe { core::arch::asm!("sync") };
        // SAFETY: stock marks the held request as started the same way.
        unsafe { channel.held_irp_started.store(1, Ordering::Relaxed) };
        return;
    }

    // SAFETY: the I/O manager passes the live request to start.
    let request = unsafe { Irp::new(irp) };
    if xboxkrnl::HalIsExecutingPowerDownDpc().get()
        || hardware_flags().contains(FAIL_OPTICAL_REQUESTS)
    {
        fail_request(channel, request);
        return;
    }

    // SAFETY: the values stock stores before it starts a request.
    unsafe {
        channel.unknown_aa.store(0, Ordering::Relaxed);
        channel.unknown_ab.store(4, Ordering::Relaxed);
    }
    trace(Trace::StartIo {
        processor: processor(),
        hotplug: HOTPLUG_FLAGS.load(Ordering::SeqCst),
        queued: QUEUED.load(Ordering::SeqCst),
        irp,
    });

    if irp == reinit_irp().0 {
        let remaining = QUEUED.fetch_sub(1, Ordering::SeqCst) - 1;
        if remaining == 0 {
            trace(Trace::StartReinit);
            schedule_reinitialize(channel);
        } else {
            trace(Trace::SkipReinit { remaining });
            check(remaining > 0);
            start_next_packet(channel);
        }
    } else if QUEUED.load(Ordering::SeqCst) == 0 && HOTPLUG_FLAGS.load(Ordering::SeqCst) == 0 {
        // SAFETY: the channel's start routine takes (channel, irp).
        unsafe {
            kernel::call_export(
                channel.start_io.load(Ordering::Relaxed),
                channel.address(),
                irp,
                0,
                0,
            )
        };
    } else {
        trace(Trace::HotplugAbort { irp });
        fail_request(channel, request);
    }
}

/// Start the reinitialization after the delay ticks (0x91f3fe50).
fn schedule_reinitialize(channel: &ChannelExtension) {
    trace(Trace::ReinitDelay {
        processor: processor(),
    });

    start_channel_timer(
        channel,
        relative_interval(Duration::from_millis(TICK_MILLISECONDS as u64)),
        TICK_MILLISECONDS,
    );

    let lock = channel.lock(Irql::DISPATCH);
    // SAFETY: the wait entry runs `start_reinitialize`, which takes the
    // channel as the timer passes it; the channel lock is held.
    unsafe {
        channel
            .wait_ticks
            .store(REINIT_DELAY_TICKS, Ordering::Relaxed);
        channel.wait_routine.store(
            start_reinitialize_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
    }
    lock.release(Irql::DISPATCH);
}

fn wait_until_ready(registers: &SataRegisters) -> bool {
    /// Status polls of 100 us while the device is busy.
    const READY_POLLS: u32 = 10_000;
    const READY_POLL_MICROSECONDS: u32 = 100;

    for _ in 0..READY_POLLS {
        if !registers.status().contains(AtaStatus::BUSY) {
            return true;
        }
        xboxkrnl::KeStallExecutionProcessor(READY_POLL_MICROSECONDS);
    }

    false
}

/// Channel wait routine: issue the reinitialization command (0x91f3fcd0,
/// `StartReinitialize`).
extern "C" fn start_reinitialize(channel: u32) {
    /// Channel timer ticks the reinitialization command may take.
    const REINIT_COMMAND_TICKS: u8 = 5;

    // SAFETY: the channel timer passes its channel extension.
    let channel = unsafe { ChannelExtension::at(channel) };
    let device = channel.device();
    // Deviation: stock loads the register address from the channel
    // extension; the constant replaces the load, as in `hotplug_dpc`.
    let registers = SataRegisters::cdrom();

    trace(Trace::StartReinitialize {
        processor: processor(),
        irp: device.current_irp(),
    });

    // Requests fail until a successful reinitialization clears the flag; one
    // that times out leaves the device disabled.
    let flags = device.flags();
    // SAFETY: the kernel fails requests while the flag is set.
    unsafe {
        flags.store(
            flags.load(Ordering::Relaxed) | DeviceObjectFlags::INITIALIZING.bits(),
            Ordering::Relaxed,
        )
    };
    HOTPLUG_FLAGS.fetch_or(HotplugState::REINITIALIZING.bits(), Ordering::SeqCst);

    let lock = channel.lock(Irql::DISPATCH);
    // SAFETY: the task file registers make the device write no memory; the
    // command transfers no data.
    unsafe { registers.device.write(0) };
    if !wait_until_ready(registers) {
        trace(Trace::DeviceBusy {
            sstatus: registers.sstatus.read(),
            scontrol: registers.scontrol.read(),
            serror: registers.serror.read(),
            status: registers.status().bits(),
        });
        xboxkrnl::DbgBreakPoint();
        // Stock returns with the channel lock held, which hangs the next
        // acquisition.
        lock.release(Irql::DISPATCH);
        return;
    }

    let command = AtaCommand::REINITIALIZE;
    // SAFETY: as above.
    unsafe {
        registers.features.write(command.features);
        registers.sector_count.write(command.sector_count);
        registers.write_command(command.command);
    }

    check(channel.interrupt_routine.load(Ordering::Relaxed) == 0);
    // SAFETY: the values stock stores before the command; the entries run
    // `reinit_interrupt` and `finish_reinitialize`, which take the
    // arguments of the channel's interrupt and completion routines. The
    // channel lock is held.
    unsafe {
        channel.unknown_88.store(0, Ordering::Relaxed);
        channel.unknown_8c.store(0, Ordering::Relaxed);
        channel.unknown_a8.store(0, Ordering::Relaxed);
        channel.interrupt_routine.store(
            reinit_interrupt_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
        channel.completion_routine.store(
            finish_reinitialize_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
        channel
            .wait_ticks
            .store(REINIT_COMMAND_TICKS, Ordering::Relaxed);
    }
    lock.release(Irql::DISPATCH);
}

/// Channel interrupt routine of the reinitialization command (0x91f3f470):
/// hand the device status to the channel DPC.
extern "C" fn reinit_interrupt(channel: u32, _registers: u32, status: u32) -> u32 {
    // SAFETY: the interrupt hook passes its channel extension.
    let channel = unsafe { ChannelExtension::at(channel) };

    // SAFETY: 0 is no routine, as stock stores it.
    unsafe { channel.interrupt_routine.store(0, Ordering::Relaxed) };

    // SAFETY: the channel DPC is an initialized DPC of the kernel's channel
    // extension.
    unsafe {
        xboxkrnl::KeInsertQueueDpc(
            core::ptr::from_ref(&channel.dpc).cast_mut().cast(),
            0,
            status,
        )
    }
    .0
}

/// Channel completion routine of the reinitialization (0x91f3fba0,
/// `FinishReinitialize`).
extern "C" fn finish_reinitialize(channel: u32, irp: u32, status: NtStatus) {
    // SAFETY: the channel DPC passes its channel extension.
    let channel = unsafe { ChannelExtension::at(channel) };
    let device = channel.device();

    trace(Trace::FinishReinitialize {
        processor: processor(),
        irp,
    });
    check(irp == reinit_irp().0);

    if status.is_success() {
        HOTPLUG_FLAGS.fetch_and(!HotplugState::REINITIALIZING.bits(), Ordering::SeqCst);
        let flags = device.flags();
        // SAFETY: clearing the flag lets the kernel pass requests again.
        unsafe {
            flags.store(
                flags.load(Ordering::Relaxed) & !DeviceObjectFlags::INITIALIZING.bits(),
                Ordering::Relaxed,
            )
        };
    } else {
        trace(Trace::ReinitTimedOut);
    }

    if INQUIRIES.fetch_add(1, Ordering::SeqCst) + 1 == 1 {
        issue_inquiry(channel);
    }

    // Stock also alerts the server thread; the server polls instead.
    DRIVE_REINITIALIZED.store(true, Ordering::Release);
    start_next_packet(channel);
}

/// Queue the inquiry request on the channel (0x91f3fa40).
fn issue_inquiry(channel: &ChannelExtension) {
    let inquiry = INQUIRY.get();
    // SAFETY: one inquiry is outstanding at a time (`INQUIRIES`), and the
    // previous one has completed.
    let request = unsafe {
        (*inquiry).data = ScsiInquiryData::new();
        (*inquiry).request = inquiry_request((&raw mut (*inquiry).data).expose_provenance() as u32);
        (&raw const (*inquiry).request).expose_provenance() as u32
    };

    let irp = Irp(INQUIRY_IRP.load(Ordering::Relaxed));
    // SAFETY: `initialize` allocated the inquiry request with the device's
    // stack size, so a stack location for the device lies below the current
    // one; the request is idle, so this module owns it.
    unsafe {
        let irp = &mut *irp.as_ptr();
        let next = irp.current_stack_location.sub(1);
        let location = &mut *next;
        location.parameters.device_control = DeviceControlParameters {
            output_length: 0,
            input_buffer: request,
            input_length: size_of::<ScsiPassThroughDirect>() as u32,
            control_code: IoControlCode::SCSI_PASS_THROUGH_DIRECT,
        };
        location.major_function = IrpMajorFunction::DeviceControl.raw();
        location.device_object = channel.device().as_ptr();
        location.completion_routine = inquiry_completion_entry as *const () as usize as u32;
        location.context = channel.address();
        location.control = IoStackControl::INVOKE_ON_CANCEL
            .union(IoStackControl::INVOKE_ON_SUCCESS)
            .union(IoStackControl::INVOKE_ON_ERROR);
        irp.user_buffer = core::ptr::null_mut();
        irp.unknown_020 = [0; 2];
        irp.current_stack_location = next;
        irp.current_location = irp.current_location.wrapping_sub(1);
    }

    start_packet(channel, irp);
}

/// Completion routine of the inquiry (0x91f3f9c0); keeps the request.
extern "C" fn inquiry_completion(_device: u32, irp: u32, channel: u32) -> NtStatus {
    // SAFETY: the I/O manager passes the completed inquiry request and the
    // channel extension `issue_inquiry` gave as the context. No other
    // inquiry is outstanding, so the data is not written.
    let (status, data, channel) = unsafe {
        (
            (*Irp(irp).as_ptr()).io_status.status,
            &(*INQUIRY.get()).data,
            ChannelExtension::at(channel),
        )
    };

    report_inquiry(status.is_success().then_some(data));
    if INQUIRIES.fetch_sub(1, Ordering::SeqCst) - 1 != 0 {
        issue_inquiry(channel);
    }

    KernelError::MoreProcessingRequired.status()
}

crate::kernel::forward!(
    /// IoSynchronousDeviceIoControlRequest with a raw `internal` word: stock
    /// passes the request size there.
    fn device_io_control(IoControlCode, *mut DeviceObject, *const ScsiPassThroughDirect, u32, *mut u8, u32, *mut u32, u32) -> NtStatus
        => xboxkrnl::IoSynchronousDeviceIoControlRequest
);

/// Identify a DVD emulator by SCSI INQUIRY of the optical drive
/// (0x91f3f918).
fn detect_dvd_emulator(device: Device) {
    let mut data = ScsiInquiryData::new();
    let request = inquiry_request((&raw mut data).expose_provenance() as u32);

    // Stock leaves the request size in r10, a nonzero BOOLEAN.
    // SAFETY: `device` is the optical drive's device object; the request
    // and the inquiry buffer it points at are live locals.
    let status = unsafe {
        device_io_control(
            IoControlCode::SCSI_PASS_THROUGH_DIRECT,
            device.as_ptr(),
            &request,
            size_of::<ScsiPassThroughDirect>() as u32,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            size_of::<ScsiPassThroughDirect>() as u32,
        )
    };

    report_inquiry(status.is_success().then_some(&data));
}

/// Record the emulator state from the inquiry data, `None` when the inquiry
/// failed, and select the matching hypervisor mode (0x91f3f7a8).
fn report_inquiry(data: Option<&ScsiInquiryData>) {
    /// The DVD emulator reports its media type in the response data format
    /// bits.
    const MEDIA_TYPE_MASK: u8 = 0xf;
    const MEDIA_TYPE_1: u8 = 1;

    let (state, message) = match data {
        None => (
            EmulatorState::empty(),
            c"XBDM: ODD SCSIOP_INQUIRY Failed.\n",
        ),
        Some(data) => {
            // SAFETY: the format is NUL-terminated and its precisions bound
            // the reads to the vendor and product fields.
            unsafe {
                DbgPrintInquiry(
                    c"XBDM: ODD VendorId=%.8s, ProductId=%.16s\n"
                        .as_ptr()
                        .cast(),
                    data.vendor_id.as_ptr(),
                    data.product_id.as_ptr(),
                )
            };

            let running = EmulatorState::RUNNING;
            if &data.vendor_id[..2] != b"MS" || &data.product_id != b"XBox 360 DVD Emu" {
                (EmulatorState::empty(), c"XBDM: DVD Emulator Not Running.\n")
            } else if &data.product_revision != b"0002" {
                (running, c"XBDM: DVD Emulator Running.\n")
            } else if data.response_format & MEDIA_TYPE_MASK == MEDIA_TYPE_1 {
                (
                    running
                        .union(EmulatorState::REVISION_0002)
                        .union(EmulatorState::MEDIA_TYPE_1),
                    c"XBDM: DVD Emulator Running.\n",
                )
            } else {
                (
                    running.union(EmulatorState::REVISION_0002),
                    c"XBDM: DVD Emulator Running.\n",
                )
            }
        }
    };

    DVD_EMULATOR_STATE.store(state.bits(), Ordering::Relaxed);
    kernel::debug_print(message);

    // SAFETY: the DVD emulation service takes no buffer.
    let enabled = unsafe {
        xboxkrnl::ExDebugMonitorService(
            DebugMonitorService::DvdEmulation,
            u32::from(!state.is_empty()),
            0,
            0,
        )
    };
    if !enabled.is_success() {
        kernel::debug_print(c"XBDM: Hypervisor DVD Emulation mode not supported.\n");
    }
}

/// Whether the DVD emulator reported revision `0002`.
pub(crate) fn emulator_revision_0002() -> bool {
    EmulatorState::from_bits_retain(DVD_EMULATOR_STATE.load(Ordering::Relaxed))
        .contains(EmulatorState::REVISION_0002)
}

/// SMC notification (0x91f3f6f0): trace the tray state messages.
extern "C" fn tray_notification(_registration: u32, message: *const SmcMessage) {
    // SAFETY: the kernel passes an SMC message.
    let message = unsafe { &*message };

    if message.0[0] == SmcCommand::TrayState.raw()
        && let Some(state) = TrayState::from_message(message.0[1])
    {
        trace(Trace::Tray { state });
    }
}

/// Server-thread part, run on every pass: append the queued trace texts to
/// the debug capture ring (dropped while capture is off), then complete a
/// finished reinitialization as the stock server loop does (0x91f510c4).
pub(crate) fn drain(server: &mut Server, console: &mut Console) {
    /// SMC message the server thread sends after a reinitialization; its
    /// meaning is unknown.
    const SMC_REINITIALIZED: [u8; 2] = [0x8b, 0x66];

    while let Some(trace) = TRACE.pop() {
        let mut text = Text::<TRACE_TEXT_CAPACITY>::new();
        trace.write(&mut text);
        debug_capture_print(&mut server.state, console, text.as_bytes());
    }

    if DRIVE_REINITIALIZED.swap(false, Ordering::AcqRel) {
        let mut message = SmcMessage::default();
        message.0[..SMC_REINITIALIZED.len()].copy_from_slice(&SMC_REINITIALIZED);
        // SAFETY: `message` is a local SMC message; no reply is requested.
        unsafe { xboxkrnl::HalSendSMCMessage(&message, core::ptr::null_mut()) };
        console.open_close_tray(0);
    }
}
