//! Optical drive SATA hot-plug support (stock DMSATA, 0x91f3f078..0x91f401e8,
//! and the tray notification 0x91f3f6f0). At startup the monitor takes over
//! the interrupt routine of the CD-ROM SATA channel and the start I/O routine
//! of the CD-ROM driver, so that a drive that is plugged in again is
//! reinitialized and probed for a DVD emulator.

use core::cell::UnsafeCell;
use core::fmt::Write as _;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicI32;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::NtStatus;
use openxbdm_server::Server;
use openxbdm_server::commands::console::TraceMask;
use openxbdm_server::commands::filesystem::Backend as _;
use openxbdm_server::commands::session::debug_capture_print;
use openxbdm_server::text::Text;

use super::Console;
use crate::exports::bridged;
use crate::kernel;
use crate::kernel::AnsiString;
use crate::kernel::current_irql;
use crate::kernel::import_thunk;
use crate::kernel::pcr;

import_thunk!(
    DbgPrintInquiry(format: *const u8, vendor: *const u8, product: *const u8) -> u32,
    lib = kernel::LIB_KERNEL,
    ordinal = 3
);

const PASSIVE_LEVEL: u8 = 0;
const DISPATCH_LEVEL: u8 = 2;

/// Processor control block; the channel lock records it as the owner.
const PCR_PRCB: u32 = 0x100;
const PCR_PROCESSOR: u32 = 0x10c;

/// Debug monitor service that returns the CD-ROM channel extension and the
/// channel's packet routines.
const DEBUG_MONITOR_CDROM_CHANNEL: u32 = 4;
/// Debug monitor service that selects hypervisor DVD emulation mode.
const DEBUG_MONITOR_DVD_EMULATION: u32 = 7;
/// Hardware flag under which every request fails; its kernel meaning is
/// unknown.
const HARDWARE_FLAG_FAIL_OPTICAL_REQUESTS: u32 = 0x4000;

const STATUS_DEVICE_REMOVED: u32 = 0xc000_02b6;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xc000_0016;

const DEVICE_DRIVER_OBJECT: u32 = 0x08;
const DEVICE_CURRENT_IRP: u32 = 0x10;
const DEVICE_FLAGS: u32 = 0x14;
const DEVICE_STACK_SIZE: u32 = 0x1e;
/// Set while the drive is reinitialized; a reinitialization that times out
/// leaves it set and the device stays disabled.
const DEVICE_FLAG_REINITIALIZING: u32 = 0x10;

const DRIVER_OBJECT_SIZE: usize = 0x38;
const DRIVER_START_IO: usize = 0;

const IRP_STATUS: u32 = 0x10;
const IRP_CURRENT_LOCATION: u32 = 0x19;
/// Words the inquiry clears before it starts the request; purpose unknown.
const IRP_CLEARED: [u32; 3] = [0x1c, 0x20, 0x24];
const IRP_STACK_LOCATION: u32 = 0x50;
const STACK_LOCATION_SIZE: u32 = 0x24;
const STACK_MAJOR_FUNCTION: u32 = 0x00;
const STACK_CONTROL: u32 = 0x03;
/// Cleared for the inquiry; purpose unknown.
const STACK_CLEARED: u32 = 0x04;
const STACK_INPUT_BUFFER: u32 = 0x08;
const STACK_INPUT_LENGTH: u32 = 0x0c;
const STACK_CONTROL_CODE: u32 = 0x10;
const STACK_DEVICE: u32 = 0x14;
const STACK_COMPLETION_ROUTINE: u32 = 0x1c;
const STACK_COMPLETION_CONTEXT: u32 = 0x20;
const INQUIRY_MAJOR_FUNCTION: u8 = 9;
/// Run the completion routine on success, error and cancel.
const STACK_INVOKE_ALWAYS: u8 = 0xe0;

/// `KDPC` byte stock sets after initialization.
const DPC_IMPORTANCE_OFFSET: usize = 3;
const DPC_IMPORTANCE: u8 = 3;
const DPC_SIZE: usize = 0x1c;

/// SATA register base (`Operational` in the stock texts).
const CHANNEL_REGISTERS: u32 = 0x00;
/// Routine `(channel, irp)` that starts a request on the channel.
const CHANNEL_START_IO: u32 = 0x04;
/// Routine `(channel, registers, status) -> BOOLEAN` the interrupt runs.
const CHANNEL_INTERRUPT_ROUTINE: u32 = 0x08;
/// Routine `(channel, irp, status)` the channel DPC runs.
const CHANNEL_COMPLETION_ROUTINE: u32 = 0x0c;
const CHANNEL_RESET_ROUTINE: u32 = 0x10;
/// Routine `(channel)` the channel timer runs once its tick count expires.
const CHANNEL_WAIT_ROUTINE: u32 = 0x14;
const CHANNEL_TIMER: u32 = 0x18;
const CHANNEL_TIMER_DPC: u32 = 0x40;
const CHANNEL_DPC: u32 = 0x5c;
const CHANNEL_DEVICE: u32 = 0x6c;
/// Cleared by the reinitialization; purpose unknown.
const CHANNEL_UNKNOWN_88: u32 = 0x88;
/// Cleared by the reinitialization; purpose unknown.
const CHANNEL_UNKNOWN_8C: u32 = 0x8c;
/// Interrupt service routine slot; the kernel passes its address to the
/// routine.
const CHANNEL_INTERRUPT: u32 = 0x90;
const CHANNEL_LOCK: u32 = 0x98;
const CHANNEL_IRQL: u32 = 0xa1;
const CHANNEL_LOCK_OWNER: u32 = 0xa4;
/// Cleared by the reinitialization; purpose unknown.
const CHANNEL_UNKNOWN_A8: u32 = 0xa8;
/// Channel timer ticks before the wait routine runs.
const CHANNEL_WAIT_TICKS: u32 = 0xa9;
/// Set to 0 by the start I/O hook; purpose unknown.
const CHANNEL_UNKNOWN_AA: u32 = 0xaa;
/// Set to 4 by the start I/O hook; purpose unknown.
const CHANNEL_UNKNOWN_AB: u32 = 0xab;
/// A request the start I/O hook only marks as started (in `CHANNEL_HELD_IRP_STARTED`).
const CHANNEL_HELD_IRP: u32 = 0xac;
const CHANNEL_HELD_IRP_STARTED: u32 = 0xd1;

/// Register base of the optical drive SATA channel, which the channel
/// extension holds in its first word (`Operational` in the stock texts).
const SATA_CDROM_REGISTERS: u32 = 0x7fea_1200;
const SATA_FEATURES: u32 = 0x01;
const SATA_SECTOR_COUNT: u32 = 0x02;
const SATA_DEVICE: u32 = 0x06;
/// Command register on write, status register on read.
const SATA_COMMAND: u32 = 0x07;
const SATA_SSTATUS: u32 = 0x10;
const SATA_SERROR: u32 = 0x14;
const SATA_SCONTROL: u32 = 0x18;
/// Hot-plug status, accessed byte-reversed.
const SATA_HOTPLUG: u32 = 0x1c;
const DEVICE_STATUS_BUSY: u8 = 0x80;
const HOTPLUG_INTERRUPT: u32 = 0x1;
const HOTPLUG_INSERTION: u32 = 0x4;
const HOTPLUG_REMOVAL: u32 = 0x8;
/// Bits written back after a removal (0x10) or an insertion (0x20); their
/// device meaning is unknown.
const HOTPLUG_REMOVED: u32 = 0x10;
const HOTPLUG_INSERTED: u32 = 0x20;
/// Device command that reinitializes the drive: features 3, count 0x42,
/// command 0xef.
const REINIT_FEATURES: u8 = 3;
const REINIT_SECTOR_COUNT: u8 = 0x42;
const REINIT_COMMAND: u8 = 0xef;
/// Status polls of 100 us while the device is busy.
const READY_POLLS: u32 = 10_000;
const READY_POLL_MICROSECONDS: u32 = 100;

/// Channel timer ticks before a queued reinitialization starts.
const REINIT_DELAY_TICKS: u8 = 3;
/// Channel timer ticks the reinitialization command may take.
const REINIT_COMMAND_TICKS: u8 = 5;
const TICK_MILLISECONDS: u32 = 100;
/// Relative due times in 100 ns units.
const TICK_DUE: i64 = -1_000_000;
const HOTPLUG_TIMER_DUE: i64 = -10_000_000;
const HOTPLUG_TIMER_PERIOD_MS: u32 = 1000;

const IOCTL_SCSI_PASS_THROUGH_DIRECT: u32 = 0x4_d014;
const PASS_THROUGH_SIZE: usize = 0x24;
const INQUIRY_LENGTH: usize = 0x24;
const SCSI_INQUIRY: u8 = 0x12;

const EMULATOR_RUNNING: u32 = 0x1;
const EMULATOR_REVISION_0002: u32 = 0x2;
const EMULATOR_MEDIA_TYPE_1: u32 = 0x4;

/// SMC message of the tray state; byte 1 is 0x60 plus the state index.
const SMC_TRAY_STATE: u8 = 0x83;
const SMC_TRAY_STATE_BASE: u8 = 0x60;
const TRAY_STATES: [&str; 7] = [
    "TRAY_OPEN",
    "TRAY_OPEN_REQUEST",
    "TRAY_CLOSE",
    "TRAY_OPENING",
    "TRAY_CLOSING",
    "TRAY_UNKNOWN",
    "TRAY_SPINUP",
];
/// SMC message the server thread sends after a reinitialization; its
/// meaning is unknown.
const SMC_REINITIALIZED: [u8; 2] = [0x8b, 0x66];
const SMC_MESSAGE_SIZE: usize = 16;

/// Longest text of the stock trace producer (0x91f3ebb0).
const TRACE_TEXT_CAPACITY: usize = 0x1ff;

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

#[repr(C, align(8))]
struct PassThrough([u8; PASS_THROUGH_SIZE]);

impl PassThrough {
    /// SCSI INQUIRY of `INQUIRY_LENGTH` bytes into `buffer`.
    fn inquiry(buffer: u32) -> Self {
        let mut request = [0u8; PASS_THROUGH_SIZE];
        request[0..2].copy_from_slice(&(PASS_THROUGH_SIZE as u16).to_be_bytes());
        request[7] = 1;
        request[8..12].copy_from_slice(&(INQUIRY_LENGTH as u32).to_be_bytes());
        request[0x10..0x14].copy_from_slice(&buffer.to_be_bytes());
        request[0x14] = SCSI_INQUIRY;
        request[0x18] = INQUIRY_LENGTH as u8;
        request[0x19] = 0xc0;
        Self(request)
    }
}

/// Request and data of the inquiry after a reinitialization (stock
/// 0x91f9fdf4 and 0x91f9fe18).
#[repr(C)]
struct Inquiry {
    request: PassThrough,
    data: [u8; INQUIRY_LENGTH],
}

/// Hot-plug DPC (stock 0x91f9fdc4).
static HOTPLUG_DPC: KernelStorage<[u8; DPC_SIZE]> = KernelStorage::new([0; DPC_SIZE]);
/// Request without stack locations queued to reinitialize the drive (stock
/// 0x91f9fde0).
static REINIT_IRP: AtomicU32 = AtomicU32::new(0);
/// Bit 0 a hot-plug event waits for the DPC, bit 1 a reinitialization runs
/// (stock 0x91f9fde4).
static HOTPLUG_FLAGS: AtomicU32 = AtomicU32::new(0);
const FLAG_EVENT_PENDING: u32 = 0x1;
const FLAG_REINITIALIZING: u32 = 0x2;
/// Reinitialization requests queued and not yet started (stock 0x91f9fde8).
static QUEUED: AtomicI32 = AtomicI32::new(0);
/// Inquiries requested and not yet completed (stock 0x91f9fdf0).
static INQUIRIES: AtomicI32 = AtomicI32::new(0);
static INQUIRY: KernelStorage<Inquiry> = KernelStorage::new(Inquiry {
    request: PassThrough([0; PASS_THROUGH_SIZE]),
    data: [0; INQUIRY_LENGTH],
});
/// Request of the inquiry (stock 0x91f9fe78).
static INQUIRY_IRP: AtomicU32 = AtomicU32::new(0);
/// Copy of the CD-ROM driver object with the start I/O hook (stock
/// 0x91f9fe7c).
static DRIVER_OBJECT: KernelStorage<[u8; DRIVER_OBJECT_SIZE]> =
    KernelStorage::new([0; DRIVER_OBJECT_SIZE]);
/// CD-ROM channel extension (stock 0x91f9feb4).
static CHANNEL: AtomicU32 = AtomicU32::new(0);
/// Channel packet routines from the debug monitor service; 0 when the
/// kernel gives none and the I/O manager routines apply (stock 0x91f9fec0,
/// 0x91f9fec4).
static START_PACKET: AtomicU32 = AtomicU32::new(0);
static START_NEXT_PACKET: AtomicU32 = AtomicU32::new(0);
/// Optical drive emulator state (stock 0x91f9fec8).
static DVD_EMULATOR_STATE: AtomicU32 = AtomicU32::new(0);
/// A reinitialization finished; the server thread completes it (stock
/// 0x91facf3c).
static DRIVE_REINITIALIZED: AtomicBool = AtomicBool::new(false);
/// SMC notification registration `{routine, 1, 0, 0}` (stock 0x91f97454).
static TRAY_REGISTRATION: KernelStorage<[u32; 4]> = KernelStorage::new([0; 4]);

/// Trace texts that can wait for the server thread; a text is dropped
/// while every slot is taken.
const TRACE_SLOTS: usize = 16;

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
        name: &'static str,
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
                const _: () = assert!(SATA_CDROM_REGISTERS == 0x7fea_1200);
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
            Self::Tray { name } => write!(text, "[XBDM] Tray notification - {name}\n"),
        };
    }
}

struct TraceRing {
    traces: [Trace; TRACE_SLOTS],
    first: usize,
    count: usize,
}

/// Traces waiting for the server thread, which appends their texts to the
/// debug capture ring.
struct TraceQueue {
    lock: UnsafeCell<u32>,
    ring: UnsafeCell<TraceRing>,
}

// SAFETY: every access to `ring` holds the spin lock.
unsafe impl Sync for TraceQueue {}

static TRACE: TraceQueue = TraceQueue {
    lock: UnsafeCell::new(0),
    ring: UnsafeCell::new(TraceRing {
        traces: [Trace::UpdatingDriver; TRACE_SLOTS],
        first: 0,
        count: 0,
    }),
};

impl TraceQueue {
    /// Queue `trace`; it is dropped when the queue is full. Above dispatch
    /// level the producer may have interrupted the lock holder, so it only
    /// tries the lock.
    fn push(&self, trace: Trace) {
        let lock = self.lock.get();
        let irql = current_irql();
        let previous = if irql < DISPATCH_LEVEL {
            Some(kernel::KfAcquireSpinLock(lock))
        } else if irql == DISPATCH_LEVEL {
            kernel::KeAcquireSpinLockAtRaisedIrql(lock);
            None
        } else if kernel::KeTryToAcquireSpinLockAtRaisedIrql(lock) & 0xff != 0 {
            None
        } else {
            return;
        };
        // SAFETY: the spin lock is held.
        let ring = unsafe { &mut *self.ring.get() };
        if ring.count < TRACE_SLOTS {
            ring.traces[(ring.first + ring.count) % TRACE_SLOTS] = trace;
            ring.count += 1;
        }
        match previous {
            Some(previous) => kernel::KfReleaseSpinLock(lock, previous),
            None => kernel::KeReleaseSpinLockFromRaisedIrql(lock),
        };
    }

    /// Take the oldest trace; called on the server thread.
    fn pop(&self) -> Option<Trace> {
        let lock = self.lock.get();
        let previous = kernel::KfAcquireSpinLock(lock);
        // SAFETY: the spin lock is held.
        let ring = unsafe { &mut *self.ring.get() };
        let trace = (ring.count != 0).then(|| {
            let trace = ring.traces[ring.first];
            ring.first = (ring.first + 1) % TRACE_SLOTS;
            ring.count -= 1;
            trace
        });
        kernel::KfReleaseSpinLock(lock, previous);
        trace
    }
}

/// Stock trace producer 0x91f3ebb0.
fn trace(trace: Trace) {
    TRACE.push(trace);
}

fn processor() -> u8 {
    read_u8(pcr() + PCR_PROCESSOR)
}

/// Stock assertion: the trap the debug routine or the kernel handles.
fn check(condition: bool) {
    if !condition {
        // SAFETY: raises the trap exception stock raises.
        unsafe { core::arch::asm!("twi 31, 0, 0x19") };
    }
}

fn eieio() {
    // SAFETY: orders the preceding register access.
    unsafe { core::arch::asm!("eieio") };
}

fn read_u8(address: u32) -> u8 {
    // SAFETY: every caller passes a kernel structure field or device
    // register stock reads at the same point.
    unsafe { core::ptr::read_volatile(address as usize as *const u8) }
}

fn write_u8(address: u32, value: u8) {
    // SAFETY: see `read_u8`.
    unsafe { core::ptr::write_volatile(address as usize as *mut u8, value) }
}

fn read_u32(address: u32) -> u32 {
    // SAFETY: see `read_u8`.
    unsafe { core::ptr::read_volatile(address as usize as *const u32) }
}

fn write_u32(address: u32, value: u32) {
    // SAFETY: see `read_u8`.
    unsafe { core::ptr::write_volatile(address as usize as *mut u32, value) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Device(u32);

impl Device {
    fn new(object: u32) -> Option<Self> {
        (object != 0).then_some(Self(object))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Irp(u32);

impl Irp {
    fn new(irp: u32) -> Option<Self> {
        (irp != 0).then_some(Self(irp))
    }
}

fn reinit_irp() -> Irp {
    Irp(REINIT_IRP.load(Ordering::Relaxed))
}

/// The SATA register block of the channel.
#[derive(Clone, Copy)]
struct SataRegisters(u32);

impl SataRegisters {
    fn read_u8(self, offset: u32) -> u8 {
        read_u8(self.0 + offset)
    }

    fn write_u8(self, offset: u32, value: u8) {
        write_u8(self.0 + offset, value);
        eieio();
    }

    fn read_reversed(self, offset: u32) -> u32 {
        read_u32(self.0 + offset).swap_bytes()
    }

    fn write_reversed(self, offset: u32, value: u32) {
        write_u32(self.0 + offset, value.swap_bytes());
        eieio();
    }
}

/// The kernel's channel extension of the CD-ROM.
#[derive(Clone, Copy)]
struct Channel(u32);

impl Channel {
    fn read(self, offset: u32) -> u32 {
        read_u32(self.0 + offset)
    }

    fn write(self, offset: u32, value: u32) {
        write_u32(self.0 + offset, value);
    }

    fn write_u8(self, offset: u32, value: u8) {
        write_u8(self.0 + offset, value);
    }

    fn registers(self) -> SataRegisters {
        SataRegisters(self.read(CHANNEL_REGISTERS))
    }

    fn device(self) -> Device {
        Device(self.read(CHANNEL_DEVICE))
    }

    fn irql(self) -> u8 {
        read_u8(self.0 + CHANNEL_IRQL)
    }

    /// Take the channel lock at the channel IRQL from `expected` IRQL.
    fn lock(self, expected: u8) -> ChannelLock {
        check(current_irql() == expected);
        kernel::KfRaiseIrql(u32::from(self.irql()));
        kernel::KeAcquireSpinLockAtRaisedIrql((self.0 + CHANNEL_LOCK) as usize as *mut u32);
        self.write(CHANNEL_LOCK_OWNER, pcr() + PCR_PRCB);
        ChannelLock(self)
    }
}

struct ChannelLock(Channel);

impl ChannelLock {
    fn release(self, irql: u8) {
        let channel = self.0;
        check(current_irql() == channel.irql());
        check(channel.read(CHANNEL_LOCK_OWNER) == pcr() + PCR_PRCB);
        kernel::KeReleaseSpinLockFromRaisedIrql((channel.0 + CHANNEL_LOCK) as usize as *mut u32);
        kernel::KfLowerIrql(u32::from(irql));
    }
}

/// A routine address the kernel provides; 0 means none.
fn routine(address: u32) -> Option<u32> {
    (address != 0).then_some(address)
}

fn start_packet(channel: Channel, irp: Irp) {
    match routine(START_PACKET.load(Ordering::Relaxed)) {
        // SAFETY: the kernel gave a routine taking (channel, irp).
        Some(routine) => unsafe { kernel::call_export(routine, channel.0, irp.0, 0, 0) },
        None => kernel::IoStartPacket(channel.device().0, irp.0, core::ptr::null()),
    };
}

fn start_next_packet(channel: Channel) {
    match routine(START_NEXT_PACKET.load(Ordering::Relaxed)) {
        // SAFETY: the kernel gave a routine taking (channel).
        Some(routine) => unsafe { kernel::call_export(routine, channel.0, 0, 0, 0) },
        None => kernel::IoStartNextPacket(channel.device().0),
    };
}

/// `KeSetTimerEx(timer, due, period, dpc)`: the console takes the due time
/// in one 64-bit register; this joins the two halves the 32-bit ABI passes.
#[unsafe(naked)]
extern "C" fn set_timer(
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
        set = sym kernel::KeSetTimerEx,
    )
}

fn start_channel_timer(channel: Channel, due: i64, period_ms: u32) {
    set_timer(
        (channel.0 + CHANNEL_TIMER) as usize as *mut u8,
        (due >> 32) as u32,
        due as u32,
        period_ms,
        (channel.0 + CHANNEL_TIMER_DPC) as usize as *mut u8,
    );
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
    // SAFETY: written before registration; the kernel reads it while
    // registered.
    unsafe {
        *TRAY_REGISTRATION.get() = [
            tray_notification_entry as *const () as usize as u32,
            1,
            0,
            0,
        ]
    };
    kernel::HalRegisterSMCNotification(TRAY_REGISTRATION.get().cast(), 1);

    let verbose = trace_mask.contains(TraceMask::CDROM);
    let name = AnsiString::new(b"\\Device\\Cdrom0");
    let mut object = 0u32;
    let found = NtStatus(kernel::ObReferenceObjectByName(&name, 0, 0, 0, &mut object)).result();
    if (found.is_err() || object == 0) && verbose {
        kernel::debug_print(c"[xbdm] Failed to find object: CdRom0.\n");
    }
    if patch(Device::new(object)).is_err() && verbose {
        kernel::debug_print(c"[xbdm] Failed to update CdRom0.\n");
    }
}

/// Why the driver was not patched; stock returns the status in each
/// comment.
enum PatchError {
    /// 0xc000000e.
    NoDevice,
    /// The kernel is not a 2.0.x.0x8000 build: 0xc000000d.
    UnsupportedKernel,
    /// 0xc0000034.
    ChannelNotFound,
    /// The channel does not belong to the device: 0xc0000005.
    InvalidChannel,
    /// 0xc0000008.
    NoDriverObject,
    /// Stock does not check the allocations.
    NoIrp,
}

/// Patch the CD-ROM driver (0x91f40088).
fn patch(device: Option<Device>) -> Result<(), PatchError> {
    let device = device.ok_or(PatchError::NoDevice)?;
    trace(Trace::UpdatingDriver);
    let version = kernel::kernel_version();
    let channel = find_channel(device, version)?;
    initialize(device)?;
    let driver = read_u32(device.0 + DEVICE_DRIVER_OBJECT);
    if driver == 0 {
        return Err(PatchError::NoDriverObject);
    }

    let irql = kernel::IoAcquireDeviceObjectLock();
    let copy = DRIVER_OBJECT.get();
    // SAFETY: the driver object holds DRIVER_OBJECT_SIZE bytes; the copy
    // is unused until the device points at it below.
    unsafe {
        core::ptr::copy_nonoverlapping(driver as usize as *const [u8; DRIVER_OBJECT_SIZE], copy, 1);
        copy.cast::<u32>()
            .add(DRIVER_START_IO)
            .write(start_io_hook_entry as *const () as usize as u32);
    }
    write_u32(device.0 + DEVICE_DRIVER_OBJECT, copy as usize as u32);
    kernel::IoReleaseDeviceObjectLock(irql);

    let lock = channel.lock(PASSIVE_LEVEL);
    channel.write(
        CHANNEL_INTERRUPT,
        interrupt_hook_entry as *const () as usize as u32,
    );
    lock.release(PASSIVE_LEVEL);
    trace(Trace::UpdatedChannelIsr);

    detect_dvd_emulator(device);
    trace(Trace::Patched { build: version[2] });
    Ok(())
}

/// Locate the channel extension of the CD-ROM (0x91f3f518,
/// `DmSataFindCdromChannelObject`).
fn find_channel(device: Device, version: [u16; 4]) -> Result<Channel, PatchError> {
    let [major, minor, build, qfe] = version;
    trace(Trace::KernelVersion(version));
    if major != 2 || minor != 0 || qfe != 0x8000 {
        return Err(PatchError::UnsupportedKernel);
    }
    let channel = match build {
        0x760 => 0x8013_7a00,
        0x8c1 | 0x8cf | 0x8d2 => 0x8013_7b20,
        0x973 | 0x974 => 0x8012_76c0,
        _ => {
            let mut data = [0u32; 8];
            let status = kernel::ExDebugMonitorService(
                DEBUG_MONITOR_CDROM_CHANNEL,
                1,
                core::mem::size_of_val(&data) as u32,
                data.as_mut_ptr() as usize as u32,
            );
            let channel = if (status as i32) < 0 {
                0
            } else {
                START_PACKET.store(data[3], Ordering::Relaxed);
                START_NEXT_PACKET.store(data[4], Ordering::Relaxed);
                data[2]
            };
            if channel == 0 {
                trace(Trace::ChannelNotFound);
                return Err(PatchError::ChannelNotFound);
            }
            channel
        }
    };
    let channel = Channel(channel);
    if channel.read(CHANNEL_REGISTERS) == SATA_CDROM_REGISTERS && channel.device() == device {
        CHANNEL.store(channel.0, Ordering::Relaxed);
        return Ok(channel);
    }
    trace(Trace::ChannelExtension(channel.0));
    trace(Trace::ChannelOperational(channel.read(CHANNEL_REGISTERS)));
    trace(Trace::CdromOperational);
    trace(Trace::ChannelDevice(channel.device().0));
    trace(Trace::CdromDevice(device.0));
    trace(Trace::InvalidChannel);
    Err(PatchError::InvalidChannel)
}

/// Prepare the hot-plug DPC and the two requests (0x91f3f498). The state
/// starts zeroed, as stock clears it here.
fn initialize(device: Device) -> Result<(), PatchError> {
    let dpc = HOTPLUG_DPC.get().cast::<u8>();
    kernel::KeInitializeDpc(
        dpc,
        hotplug_dpc_entry as *const () as usize,
        device.0 as usize,
    );
    // SAFETY: the byte lies inside the initialized DPC.
    unsafe { dpc.add(DPC_IMPORTANCE_OFFSET).write(DPC_IMPORTANCE) };
    let reinit = Irp::new(kernel::IoAllocateIrp(0));
    let inquiry = Irp::new(kernel::IoAllocateIrp(u32::from(read_u8(
        device.0 + DEVICE_STACK_SIZE,
    ))));
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
    let channel = Channel(interrupt - CHANNEL_INTERRUPT);
    check(registers == SATA_CDROM_REGISTERS);
    let registers = SataRegisters(registers);
    let device_status = registers.read_u8(SATA_COMMAND);
    let hotplug = registers.read_reversed(SATA_HOTPLUG);
    if hotplug & HOTPLUG_INTERRUPT != 0 && hotplug & (HOTPLUG_INSERTION | HOTPLUG_REMOVAL) != 0 {
        registers.write_reversed(
            SATA_HOTPLUG,
            hotplug & !(HOTPLUG_REMOVED | HOTPLUG_INSERTED),
        );
        HOTPLUG_FLAGS.fetch_or(FLAG_EVENT_PENDING, Ordering::SeqCst);
        return kernel::KeInsertQueueDpc(HOTPLUG_DPC.get().cast(), channel.0, hotplug);
    }
    match routine(channel.read(CHANNEL_INTERRUPT_ROUTINE)) {
        // SAFETY: the channel's interrupt routine takes (channel,
        // registers, status).
        Some(routine) => unsafe {
            kernel::call_export(routine, channel.0, registers.0, u32::from(device_status), 0)
        },
        // Stock returns the channel address, still in r3, as the result.
        None => channel.0,
    }
}

/// Hot-plug DPC (0x91f3f180): acknowledge a removal, or cancel the
/// channel's work and queue a reinitialization after an insertion.
extern "C" fn hotplug_dpc(_dpc: u32, device: u32, channel: u32, hotplug: u32) {
    let channel = Channel(channel);
    let registers = channel.registers();
    let acknowledge = hotplug & !(HOTPLUG_REMOVED | HOTPLUG_INSERTED);
    let acknowledge = if hotplug & HOTPLUG_REMOVAL != 0 {
        acknowledge | HOTPLUG_REMOVED
    } else {
        trace(Trace::PlugIn {
            processor: processor(),
        });
        queue_reinitialize(Device(device), channel);
        acknowledge | HOTPLUG_INSERTED
    };
    registers.write_reversed(SATA_HOTPLUG, acknowledge);
}

fn queue_reinitialize(device: Device, channel: Channel) {
    let lock = channel.lock(DISPATCH_LEVEL);
    let wait = channel.read(CHANNEL_WAIT_ROUTINE);
    let reset = channel.read(CHANNEL_RESET_ROUTINE);
    let interrupt = channel.read(CHANNEL_INTERRUPT_ROUTINE);
    let current = read_u32(device.0 + DEVICE_CURRENT_IRP);
    let mut restart_timer = false;
    let mut abort_current = false;
    if wait != 0 {
        let reinitializing = current == reinit_irp().0;
        trace(Trace::CancellingWait { reinitializing });
        restart_timer = true;
        channel.write(CHANNEL_WAIT_ROUTINE, 0);
        abort_current = true;
    }
    if reset != 0 {
        trace(Trace::CancellingReset);
        restart_timer = true;
        channel.write(CHANNEL_RESET_ROUTINE, 0);
    }
    if interrupt != 0 {
        trace(Trace::CancellingRequest);
        abort_current = true;
        channel.write(CHANNEL_INTERRUPT_ROUTINE, 0);
    }
    QUEUED.fetch_add(1, Ordering::SeqCst);
    HOTPLUG_FLAGS.fetch_and(!FLAG_EVENT_PENDING, Ordering::SeqCst);
    check(channel.read(CHANNEL_INTERRUPT_ROUTINE) == 0);
    check(channel.read(CHANNEL_WAIT_ROUTINE) == 0);
    check(channel.read(CHANNEL_RESET_ROUTINE) == 0);
    lock.release(DISPATCH_LEVEL);

    if restart_timer {
        start_channel_timer(channel, HOTPLUG_TIMER_DUE, HOTPLUG_TIMER_PERIOD_MS);
    }
    trace(Trace::QueueReinit {
        queued: QUEUED.load(Ordering::SeqCst),
    });
    start_packet(channel, reinit_irp());
    if abort_current {
        trace(Trace::AbortPending { irp: current });
        fail_request(channel, Irp::new(current));
    }
}

/// Complete `irp` as removed, unless it is the reinitialization request,
/// and start the next request (0x91f3f0d8).
fn fail_request(channel: Channel, irp: Option<Irp>) {
    check(irp.is_some());
    check(current_irql() == DISPATCH_LEVEL);
    if let Some(irp) = irp
        && irp != reinit_irp()
    {
        write_u32(irp.0 + IRP_STATUS, STATUS_DEVICE_REMOVED);
        kernel::IoCompleteRequest(irp.0, 0);
    }
    start_next_packet(channel);
}

/// Start I/O routine of the driver object copy (0x91f3ff10,
/// `DmSataCdRomStartIo`).
extern "C" fn start_io_hook(_device: u32, irp: u32) {
    let channel = Channel(CHANNEL.load(Ordering::Relaxed));
    if irp == channel.read(CHANNEL_HELD_IRP) {
        // SAFETY: a full memory barrier, as stock issues before the store.
        unsafe { core::arch::asm!("sync") };
        channel.write_u8(CHANNEL_HELD_IRP_STARTED, 1);
        return;
    }
    if kernel::HalIsExecutingPowerDownDpc() != 0
        || kernel::hardware_flags() & HARDWARE_FLAG_FAIL_OPTICAL_REQUESTS != 0
    {
        fail_request(channel, Irp::new(irp));
        return;
    }
    channel.write_u8(CHANNEL_UNKNOWN_AA, 0);
    channel.write_u8(CHANNEL_UNKNOWN_AB, 4);
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
        unsafe { kernel::call_export(channel.read(CHANNEL_START_IO), channel.0, irp, 0, 0) };
    } else {
        trace(Trace::HotplugAbort { irp });
        fail_request(channel, Irp::new(irp));
    }
}

/// Start the reinitialization after the delay ticks (0x91f3fe50).
fn schedule_reinitialize(channel: Channel) {
    trace(Trace::ReinitDelay {
        processor: processor(),
    });
    start_channel_timer(channel, TICK_DUE, TICK_MILLISECONDS);
    let lock = channel.lock(DISPATCH_LEVEL);
    channel.write_u8(CHANNEL_WAIT_TICKS, REINIT_DELAY_TICKS);
    channel.write(
        CHANNEL_WAIT_ROUTINE,
        start_reinitialize_entry as *const () as usize as u32,
    );
    lock.release(DISPATCH_LEVEL);
}

fn wait_until_ready(registers: SataRegisters) -> bool {
    for _ in 0..READY_POLLS {
        if registers.read_u8(SATA_COMMAND) & DEVICE_STATUS_BUSY == 0 {
            return true;
        }
        kernel::KeStallExecutionProcessor(READY_POLL_MICROSECONDS);
    }
    false
}

/// Channel wait routine: issue the reinitialization command (0x91f3fcd0,
/// `StartReinitialize`).
extern "C" fn start_reinitialize(channel: u32) {
    let channel = Channel(channel);
    let device = channel.device();
    let registers = channel.registers();
    trace(Trace::StartReinitialize {
        processor: processor(),
        irp: read_u32(device.0 + DEVICE_CURRENT_IRP),
    });
    write_u32(
        device.0 + DEVICE_FLAGS,
        read_u32(device.0 + DEVICE_FLAGS) | DEVICE_FLAG_REINITIALIZING,
    );
    HOTPLUG_FLAGS.fetch_or(FLAG_REINITIALIZING, Ordering::SeqCst);
    let lock = channel.lock(DISPATCH_LEVEL);
    registers.write_u8(SATA_DEVICE, 0);
    if !wait_until_ready(registers) {
        let sstatus = registers.read_reversed(SATA_SSTATUS);
        let scontrol = registers.read_reversed(SATA_SCONTROL);
        let serror = registers.read_reversed(SATA_SERROR);
        let status = registers.read_u8(SATA_COMMAND);
        trace(Trace::DeviceBusy {
            sstatus,
            scontrol,
            serror,
            status,
        });
        kernel::DbgBreakPoint();
        // Stock returns with the channel lock held, which hangs the next
        // acquisition.
        lock.release(DISPATCH_LEVEL);
        return;
    }
    registers.write_u8(SATA_FEATURES, REINIT_FEATURES);
    registers.write_u8(SATA_SECTOR_COUNT, REINIT_SECTOR_COUNT);
    registers.write_u8(SATA_COMMAND, REINIT_COMMAND);
    check(channel.read(CHANNEL_INTERRUPT_ROUTINE) == 0);
    channel.write(CHANNEL_UNKNOWN_88, 0);
    channel.write(CHANNEL_UNKNOWN_8C, 0);
    channel.write_u8(CHANNEL_UNKNOWN_A8, 0);
    channel.write(
        CHANNEL_INTERRUPT_ROUTINE,
        reinit_interrupt_entry as *const () as usize as u32,
    );
    channel.write(
        CHANNEL_COMPLETION_ROUTINE,
        finish_reinitialize_entry as *const () as usize as u32,
    );
    channel.write_u8(CHANNEL_WAIT_TICKS, REINIT_COMMAND_TICKS);
    lock.release(DISPATCH_LEVEL);
}

/// Channel interrupt routine of the reinitialization command (0x91f3f470):
/// hand the device status to the channel DPC.
extern "C" fn reinit_interrupt(channel: u32, _registers: u32, status: u32) -> u32 {
    let channel = Channel(channel);
    channel.write(CHANNEL_INTERRUPT_ROUTINE, 0);
    kernel::KeInsertQueueDpc((channel.0 + CHANNEL_DPC) as usize as *mut u8, 0, status)
}

/// Channel completion routine of the reinitialization (0x91f3fba0,
/// `FinishReinitialize`).
extern "C" fn finish_reinitialize(channel: u32, irp: u32, status: u32) {
    let channel = Channel(channel);
    let device = channel.device();
    trace(Trace::FinishReinitialize {
        processor: processor(),
        irp,
    });
    check(irp == reinit_irp().0);
    if (status as i32) >= 0 {
        HOTPLUG_FLAGS.fetch_and(!FLAG_REINITIALIZING, Ordering::SeqCst);
        write_u32(
            device.0 + DEVICE_FLAGS,
            read_u32(device.0 + DEVICE_FLAGS) & !DEVICE_FLAG_REINITIALIZING,
        );
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
fn issue_inquiry(channel: Channel) {
    let inquiry = INQUIRY.get();
    // SAFETY: one inquiry is outstanding at a time (`INQUIRIES`), and the
    // previous one has completed.
    let request = unsafe {
        (*inquiry).data = [0; INQUIRY_LENGTH];
        (*inquiry).request =
            PassThrough::inquiry(core::ptr::addr_of_mut!((*inquiry).data) as usize as u32);
        core::ptr::addr_of!((*inquiry).request) as usize as u32
    };
    let irp = INQUIRY_IRP.load(Ordering::Relaxed);
    let next = read_u32(irp + IRP_STACK_LOCATION) - STACK_LOCATION_SIZE;
    write_u32(next + STACK_CONTROL_CODE, IOCTL_SCSI_PASS_THROUGH_DIRECT);
    write_u32(next + STACK_CLEARED, 0);
    write_u8(next + STACK_MAJOR_FUNCTION, INQUIRY_MAJOR_FUNCTION);
    write_u32(next + STACK_INPUT_BUFFER, request);
    write_u32(next + STACK_INPUT_LENGTH, PASS_THROUGH_SIZE as u32);
    write_u32(next + STACK_DEVICE, channel.device().0);
    write_u32(
        next + STACK_COMPLETION_ROUTINE,
        inquiry_completion_entry as *const () as usize as u32,
    );
    write_u32(next + STACK_COMPLETION_CONTEXT, channel.0);
    write_u8(next + STACK_CONTROL, STACK_INVOKE_ALWAYS);
    for offset in IRP_CLEARED {
        write_u32(irp + offset, 0);
    }
    write_u32(irp + IRP_STACK_LOCATION, next);
    write_u8(
        irp + IRP_CURRENT_LOCATION,
        read_u8(irp + IRP_CURRENT_LOCATION).wrapping_sub(1),
    );
    start_packet(channel, Irp(irp));
}

/// Completion routine of the inquiry (0x91f3f9c0); keeps the request.
extern "C" fn inquiry_completion(_device: u32, irp: u32, channel: u32) -> u32 {
    // SAFETY: the request that filled the data has completed and no other
    // inquiry is outstanding.
    report_inquiry(read_u32(irp + IRP_STATUS), unsafe {
        &(*INQUIRY.get()).data
    });
    if INQUIRIES.fetch_sub(1, Ordering::SeqCst) - 1 != 0 {
        issue_inquiry(Channel(channel));
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

/// Identify a DVD emulator by SCSI INQUIRY of the optical drive
/// (0x91f3f918).
fn detect_dvd_emulator(device: Device) {
    let mut data = [0u8; INQUIRY_LENGTH];
    let request = PassThrough::inquiry(data.as_mut_ptr() as usize as u32);
    // The last argument is the value stock leaves in r10 from the request.
    let status = kernel::IoSynchronousDeviceIoControlRequest(
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        device.0,
        request.0.as_ptr(),
        PASS_THROUGH_SIZE as u32,
        core::ptr::null_mut(),
        0,
        core::ptr::null_mut(),
        PASS_THROUGH_SIZE as u32,
    );
    report_inquiry(status, &data);
}

/// Record the emulator state from inquiry data and select the matching
/// hypervisor mode (0x91f3f7a8).
fn report_inquiry(status: u32, data: &[u8; INQUIRY_LENGTH]) {
    let (state, message) = if (status as i32) < 0 {
        (0, c"XBDM: ODD SCSIOP_INQUIRY Failed.\n")
    } else {
        DbgPrintInquiry(
            c"XBDM: ODD VendorId=%.8s, ProductId=%.16s\n"
                .as_ptr()
                .cast(),
            data[8..].as_ptr(),
            data[0x10..].as_ptr(),
        );
        if &data[8..10] != b"MS" || &data[0x10..0x20] != b"XBox 360 DVD Emu" {
            (0, c"XBDM: DVD Emulator Not Running.\n")
        } else if &data[0x20..0x24] != b"0002" {
            (EMULATOR_RUNNING, c"XBDM: DVD Emulator Running.\n")
        } else if data[3] & 0xf == 1 {
            (
                EMULATOR_RUNNING | EMULATOR_REVISION_0002 | EMULATOR_MEDIA_TYPE_1,
                c"XBDM: DVD Emulator Running.\n",
            )
        } else {
            (
                EMULATOR_RUNNING | EMULATOR_REVISION_0002,
                c"XBDM: DVD Emulator Running.\n",
            )
        }
    };
    DVD_EMULATOR_STATE.store(state, Ordering::Relaxed);
    kernel::debug_print(message);
    if (kernel::ExDebugMonitorService(DEBUG_MONITOR_DVD_EMULATION, u32::from(state != 0), 0, 0)
        as i32)
        < 0
    {
        kernel::debug_print(c"XBDM: Hypervisor DVD Emulation mode not supported.\n");
    }
}

/// Whether the DVD emulator reported revision `0002`.
pub(crate) fn emulator_revision_0002() -> bool {
    DVD_EMULATOR_STATE.load(Ordering::Relaxed) & EMULATOR_REVISION_0002 != 0
}

/// SMC notification (0x91f3f6f0): trace the tray state messages.
extern "C" fn tray_notification(_registration: u32, message: *const u8) {
    // SAFETY: the kernel passes an SMC message of SMC_MESSAGE_SIZE bytes.
    let (kind, state) = unsafe { (*message, *message.add(1)) };
    if kind == SMC_TRAY_STATE
        && let Some(&name) = TRAY_STATES.get(usize::from(state.wrapping_sub(SMC_TRAY_STATE_BASE)))
    {
        trace(Trace::Tray { name });
    }
}

/// Server-thread part, run on every pass: append the queued trace texts to
/// the debug capture ring (dropped while capture is off), then complete a
/// finished reinitialization as the stock server loop does (0x91f510c4).
pub(crate) fn drain(server: &mut Server, console: &mut Console) {
    while let Some(trace) = TRACE.pop() {
        let mut text = Text::<TRACE_TEXT_CAPACITY>::new();
        trace.write(&mut text);
        debug_capture_print(&mut server.state, console, text.as_bytes());
    }
    if DRIVE_REINITIALIZED.swap(false, Ordering::AcqRel) {
        let mut message = [0u8; SMC_MESSAGE_SIZE];
        message[..SMC_REINITIALIZED.len()].copy_from_slice(&SMC_REINITIALIZED);
        kernel::HalSendSMCMessage(message.as_ptr(), core::ptr::null_mut());
        console.open_close_tray(0);
    }
}
