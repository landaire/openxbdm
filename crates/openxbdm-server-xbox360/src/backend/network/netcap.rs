//! `netcap` services: the frame callbacks append records to a buffered
//! capture file that a writer thread drains (frame-log library
//! 0x91f67f78..0x91f6b4e8).

mod writer;

use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netcap;
use openxbdm_server::commands::network::netcap::CaptureClose;
use openxbdm_server::commands::network::netcap::CaptureFlags;
use openxbdm_server::commands::network::netcap::CaptureRequest;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::Admission;
use openxbdm_server::commands::network::netcap::capture_file::CaptureFileError;
use openxbdm_server::commands::network::netcap::capture_file::Clock;
use openxbdm_server::commands::network::netcap::capture_file::LocalTime;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;
use xbox360::status::KernelError;
use xbox360::status::NtStatus;
use xbox360::sync::SpinLock;
use xbox360::time::Timebase;
use xbox360_sys::xam;
use xbox360_sys::xam::EthernetInterceptFlags;
use xbox360_sys::xam::NetDll_XNetSetOpt;
use xbox360_sys::xam::NetDll_XnpEthernetInterceptSetCallbacks;
use xbox360_sys::xam::SystemTime;
use xbox360_sys::xam::XnCaller;
use xbox360_sys::xam::XnetOption;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::PoolTag;
use xbox360_sys::xboxkrnl::PoolType;

use self::writer::Writer;
use super::FrameHook;
use crate::backend::Console;
use crate::kernel;

/// Frame accounting shared with the frame callbacks.
struct Accounting {
    recorder: Recorder,
    clock: Clock,
}

/// Capture context in pool memory, shared with the frame callbacks.
struct Context {
    accounting: SpinLock<Accounting>,
    /// Flags the callbacks apply (0x91f9f694).
    flags: AtomicU32,
    error: CallbackError,
    writer: Writer,
}

impl Context {
    /// Append one frame (0x91f699f8).
    fn append(&self, frame: &[u8]) -> Result<(), CaptureFileError> {
        let now = Timebase::now().ticks();
        let length = frame.len() as u32;

        let mut accounting = self.accounting.lock();
        match accounting.recorder.admit(length) {
            Err(error) => Err(error),
            Ok(Admission::Discard) => Ok(()),
            Ok(Admission::Record) => {
                let header = capture_file::record_header(accounting.clock.timestamp(now), length);
                let written = self
                    .writer
                    .put(&header, false)
                    .and_then(|()| self.writer.put(frame, false))
                    .and_then(|()| self.writer.put(&capture_file::RECORD_TRAILER, true));

                match written {
                    Ok(()) => accounting.recorder.recorded(length),
                    Err(error) => accounting.recorder.failed(error),
                }

                written
            }
        }
    }

    /// Callback body (0x91f34de0): record the frame unless a frame already
    /// failed; keep the first failure.
    fn record(&self, frame: &[u8]) {
        if self.error.is_set() {
            return;
        }

        if let Err(error) = self.append(frame) {
            self.error.keep_first(error);
        }
    }
}

/// The first failing callback result (0x91f9f698) in one word that the
/// callbacks update without the lock: 0 for none, 1..=5 for the capture
/// file's own errors, else the status of a failed kernel call (high bit
/// set).
struct CallbackError(AtomicU32);

impl CallbackError {
    const NONE: u32 = 0;

    const fn new() -> Self {
        Self(AtomicU32::new(Self::NONE))
    }

    fn is_set(&self) -> bool {
        self.0.load(Ordering::Acquire) != Self::NONE
    }

    fn get(&self) -> Option<CaptureFileError> {
        Some(match self.0.load(Ordering::Acquire) {
            Self::NONE => return None,
            1 => CaptureFileError::BadLength,
            2 => CaptureFileError::DataLimitReached,
            3 => CaptureFileError::WriteFault,
            4 => CaptureFileError::InvalidData,
            5 => CaptureFileError::OutOfMemory,
            status => CaptureFileError::Kernel(KernelError::from_status(NtStatus(status))?),
        })
    }

    fn clear(&self) {
        self.0.store(Self::NONE, Ordering::Release);
    }

    /// Store `error` unless a failure is stored.
    fn keep_first(&self, error: CaptureFileError) {
        let word = match error {
            CaptureFileError::BadLength => 1,
            CaptureFileError::DataLimitReached => 2,
            CaptureFileError::WriteFault => 3,
            CaptureFileError::InvalidData => 4,
            CaptureFileError::OutOfMemory => 5,
            CaptureFileError::Kernel(error) => error.status().0,
        };

        let _ = self
            .0
            .compare_exchange(Self::NONE, word, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Platform state of `netcap`.
pub struct Data {
    /// Capture context (0x91f9f690 once attached).
    context: Option<NonNull<Context>>,
    attached: bool,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            context: None,
            attached: false,
        }
    }

    /// Callbacks of the running capture, for chaining into the network
    /// simulator.
    pub(crate) fn hook(&self) -> Option<FrameHook> {
        let context = self.context.filter(|_| self.attached)?;

        Some(FrameHook {
            transmit,
            receive,
            context: context.as_ptr() as usize,
        })
    }

    fn context(&self) -> Option<&Context> {
        // SAFETY: the context stays allocated until `close_capture` takes it.
        self.context.map(|context| unsafe { context.as_ref() })
    }
}

impl netcap::Backend for Console {
    fn open_capture(&mut self, request: &CaptureRequest<'_>) -> Result<(), CaptureFileError> {
        /// Pool tag of capture allocations (`DMNC`).
        const CAPTURE_TAG: PoolTag = PoolTag::new(*b"DMNC");
        /// Pool types of the allocator stubs 0x91f34f70 and 0x91f34f60.
        const TITLE_POOL: PoolType = PoolType::Title;
        const PERSISTENT_POOL: PoolType = PoolType::System;

        let pool = if request.flags.contains(CaptureFlags::PERSISTENT) {
            PERSISTENT_POOL
        } else {
            TITLE_POOL
        };

        // SAFETY: pool allocation of a fixed size; the result is checked below.
        let memory = unsafe {
            xboxkrnl::ExAllocatePoolTypeWithTag(
                core::mem::size_of::<Context>() as u32,
                CAPTURE_TAG,
                pool,
            )
        };
        let Some(context) = NonNull::new(memory as usize as *mut Context) else {
            return Err(CaptureFileError::OutOfMemory);
        };

        let start = local_time();
        let clock = Clock::new(Timebase::now().ticks(), kernel::performance_frequency());
        // SAFETY: the allocation is large enough and suitably aligned for a
        // `Context`; the writer initializes in place because its event links
        // to itself.
        let context = unsafe {
            context.as_ptr().write(Context {
                accounting: SpinLock::new(Accounting {
                    recorder: Recorder::new(request.data_limit),
                    clock,
                }),
                flags: AtomicU32::new(0),
                error: CallbackError::new(),
                writer: Writer::new(),
            });
            context
        };

        // SAFETY: initialized above; no callback can reach it yet.
        let opened = unsafe { context.as_ref() }.writer.open(
            request.path,
            request.sizes,
            &capture_file::file_header(&start),
            pool,
            CAPTURE_TAG,
        );
        if let Err(error) = opened {
            // SAFETY: the context was allocated above and no callback can reach it.
            unsafe { xboxkrnl::ExFreePool(context.as_ptr() as usize as u32) };
            return Err(error);
        }

        self.network.netcap.context = Some(context);

        Ok(())
    }

    fn set_promiscuous(&mut self, enable: bool) -> bool {
        let value = u32::from(enable);
        // SAFETY: `value` is a live u32 option value of the stated size.
        let error = unsafe {
            NetDll_XNetSetOpt(
                XnCaller::SystemApp,
                XnetOption::PROMISCUOUS,
                (&raw const value).cast(),
                size_of::<u32>() as u32,
            )
        };

        error == 0
    }

    fn attach_capture(&mut self, flags: CaptureFlags) -> Result<(), WsaError> {
        let Some(pointer) = self.network.netcap.context else {
            return Ok(());
        };

        // SAFETY: the context stays allocated until `close_capture` takes it.
        let context = unsafe { pointer.as_ref() };
        context.error.clear();
        context.flags.store(flags.bits(), Ordering::Release);

        let hook = FrameHook {
            transmit,
            receive,
            context: pointer.as_ptr() as usize,
        };

        if !super::netsim::chain_capture(self, Some(hook)) {
            // SAFETY: the entries take `hook.context`, which stays allocated
            // until `close_capture`, after `detach_capture` removes the hook.
            let error = unsafe {
                NetDll_XnpEthernetInterceptSetCallbacks(
                    XnCaller::SystemApp,
                    transmit_entry as *const () as usize,
                    receive_entry as *const () as usize,
                    hook.context,
                    EthernetInterceptFlags::empty().bits(),
                )
            };

            if let Some(error) = WsaError::new(error) {
                return Err(error);
            }
        }

        self.network.netcap.attached = true;

        Ok(())
    }

    fn detach_capture(&mut self) {
        if !super::netsim::chain_capture(self, None) {
            // SAFETY: clearing the callbacks passes no pointers.
            unsafe {
                NetDll_XnpEthernetInterceptSetCallbacks(
                    XnCaller::SystemApp,
                    0,
                    0,
                    0,
                    EthernetInterceptFlags::empty().bits(),
                )
            };
        }

        self.network.netcap.attached = false;
    }

    fn capture_error(&self) -> Option<CaptureFileError> {
        self.network.netcap.context()?.error.get()
    }

    fn close_capture(&mut self) -> CaptureClose {
        self.network.netcap.attached = false;

        let Some(pointer) = self.network.netcap.context.take() else {
            return CaptureClose {
                result: Ok(()),
                frames: 0,
            };
        };

        // SAFETY: taken from `Data`; freed below.
        let context = unsafe { pointer.as_ref() };
        // Frames arriving from now on are discarded, so the copy stays
        // current.
        let mut recorder = {
            let mut accounting = context.accounting.lock();
            accounting.recorder.begin_close();
            accounting.recorder
        };

        let result = context.writer.finish(&mut recorder);
        let frames = recorder.frames();
        context.writer.release();

        // SAFETY: the context was taken from `Data` and the writer is released.
        unsafe { xboxkrnl::ExFreePool(pointer.as_ptr() as usize as u32) };

        CaptureClose { result, frames }
    }
}

/// # Safety
///
/// `context` is a live [`Context`]; `frame` holds `length` bytes.
unsafe fn frame_parts<'a>(context: usize, frame: *mut u8, length: u32) -> (&'a Context, &'a [u8]) {
    // SAFETY: guaranteed by the caller.
    unsafe {
        (
            &*(context as *const Context),
            core::slice::from_raw_parts(frame, length as usize),
        )
    }
}

crate::exports::bridged!(pub(super) transmit_entry, transmit);
crate::exports::bridged!(pub(super) receive_entry, receive);

/// Transmit callback (0x91f34de0); never consumes the frame.
extern "C" fn transmit(context: usize, frame: *mut u8, length: u32) -> u32 {
    // SAFETY: the network stack passes the context registered with the
    // callbacks and a frame of `length` bytes.
    let (context, frame) = unsafe { frame_parts(context, frame, length) };
    context.record(frame);

    0
}

/// Receive callback (0x91f34e78); applies the group address filters.
extern "C" fn receive(context: usize, frame: *mut u8, length: u32) -> u32 {
    // SAFETY: as for `transmit`.
    let (context, frame) = unsafe { frame_parts(context, frame, length) };

    if !context.error.is_set()
        && !CaptureFlags::from_bits_retain(context.flags.load(Ordering::Acquire))
            .skips_received(frame)
    {
        context.record(frame);
    }

    0
}

fn local_time() -> LocalTime {
    let mut time = SystemTime::default();
    // SAFETY: `time` is a live SYSTEMTIME.
    unsafe { xam::GetLocalTime(&mut time) };

    LocalTime {
        year: time.year,
        month: time.month,
        day_of_week: time.day_of_week,
        day: time.day,
        hour: time.hour,
        minute: time.minute,
        second: time.second,
        millisecond: time.milliseconds,
    }
}
