//! `netcap` services: the frame callbacks append records to a buffered
//! capture file that a writer thread drains (frame-log library
//! 0x91f67f78..0x91f6b4e8).

mod writer;

use core::ptr::NonNull;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_core::status::Hresult;
use openxbdm_server::commands::network::WsaError;
use openxbdm_server::commands::network::netcap;
use openxbdm_server::commands::network::netcap::CaptureClose;
use openxbdm_server::commands::network::netcap::CaptureFlags;
use openxbdm_server::commands::network::netcap::CaptureRequest;
use openxbdm_server::commands::network::netcap::capture_file;
use openxbdm_server::commands::network::netcap::capture_file::Admission;
use openxbdm_server::commands::network::netcap::capture_file::Clock;
use openxbdm_server::commands::network::netcap::capture_file::LocalTime;
use openxbdm_server::commands::network::netcap::capture_file::Recorder;

use self::writer::Writer;
use super::FrameHook;
use super::NetDll_XNetSetOpt;
use super::NetDll_XnpEthernetInterceptSetCallbacks;
use super::XNCALLER_SYSAPP;
use crate::backend::Console;
use crate::kernel;
use crate::kernel::SpinLocked;

/// Pool tag of capture allocations (`DMNC`).
const CAPTURE_TAG: u32 = 0x444d_4e43;
/// `XNetSetOpt` option for promiscuous receive.
const XNET_OPT_PROMISCUOUS: u32 = 0x1390;
/// Pool types of the allocator stubs 0x91f34f70 and 0x91f34f60.
const TITLE_POOL: u32 = 1;
const PERSISTENT_POOL: u32 = 2;

/// Frame accounting shared with the frame callbacks.
struct Accounting {
    recorder: Recorder,
    clock: Clock,
}

/// Capture context in pool memory, shared with the frame callbacks.
struct Context {
    accounting: SpinLocked<Accounting>,
    /// Flags the callbacks apply (0x91f9f694).
    flags: AtomicU32,
    /// First failing callback result, 0 for none (0x91f9f698).
    error: AtomicU32,
    writer: Writer,
}

impl Context {
    /// Append one frame (0x91f699f8).
    fn append(&self, frame: &[u8]) -> Result<(), Hresult> {
        let now = kernel::timebase();
        let length = frame.len() as u32;
        self.accounting
            .with(|accounting| match accounting.recorder.admit(length) {
                Err(error) => Err(error),
                Ok(Admission::Discard) => Ok(()),
                Ok(Admission::Record) => {
                    let header =
                        capture_file::record_header(accounting.clock.timestamp(now), length);
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
            })
    }

    /// Callback body (0x91f34de0): record the frame unless a frame already
    /// failed; keep the first failure.
    fn record(&self, frame: &[u8]) {
        if self.error.load(Ordering::Acquire) != 0 {
            return;
        }
        if let Err(error) = self.append(frame) {
            let _ = self
                .error
                .compare_exchange(0, error.0, Ordering::AcqRel, Ordering::Acquire);
        }
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
    if context.error.load(Ordering::Acquire) == 0
        && !CaptureFlags(context.flags.load(Ordering::Acquire)).skips_received(frame)
    {
        context.record(frame);
    }
    0
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

fn local_time() -> LocalTime {
    let mut fields = [0u16; 8];
    kernel::GetLocalTime(fields.as_mut_ptr());
    let [
        year,
        month,
        day_of_week,
        day,
        hour,
        minute,
        second,
        millisecond,
    ] = fields;
    LocalTime {
        year,
        month,
        day_of_week,
        day,
        hour,
        minute,
        second,
        millisecond,
    }
}

impl netcap::Backend for Console {
    fn open_capture(&mut self, request: &CaptureRequest<'_>) -> Result<(), Hresult> {
        let pool = if request.flags.contains(CaptureFlags::PERSISTENT) {
            PERSISTENT_POOL
        } else {
            TITLE_POOL
        };
        let memory = kernel::ExAllocatePoolTypeWithTag(
            core::mem::size_of::<Context>() as u32,
            CAPTURE_TAG,
            pool,
        );
        let Some(context) = NonNull::new(memory as usize as *mut Context) else {
            return Err(Hresult::OUT_OF_MEMORY);
        };
        let start = local_time();
        let clock = Clock::new(kernel::timebase(), kernel::performance_frequency());
        // SAFETY: the allocation is large enough and suitably aligned for a
        // `Context`; the writer initializes in place because its event links
        // to itself.
        let context = unsafe {
            context.as_ptr().write(Context {
                accounting: SpinLocked::new(Accounting {
                    recorder: Recorder::new(request.data_limit),
                    clock,
                }),
                flags: AtomicU32::new(0),
                error: AtomicU32::new(0),
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
            kernel::ExFreePool(context.as_ptr() as usize as u32);
            return Err(error);
        }
        self.network.netcap.context = Some(context);
        Ok(())
    }

    fn set_promiscuous(&mut self, enable: bool) -> bool {
        let value = u32::from(enable);
        NetDll_XNetSetOpt(
            XNCALLER_SYSAPP,
            XNET_OPT_PROMISCUOUS,
            (&raw const value).cast(),
            4,
        ) == 0
    }

    fn attach_capture(&mut self, flags: CaptureFlags) -> Result<(), WsaError> {
        let Some(pointer) = self.network.netcap.context else {
            return Ok(());
        };
        // SAFETY: the context stays allocated until `close_capture` takes it.
        let context = unsafe { pointer.as_ref() };
        context.error.store(0, Ordering::Release);
        context.flags.store(flags.0, Ordering::Release);
        let hook = FrameHook {
            transmit,
            receive,
            context: pointer.as_ptr() as usize,
        };
        if !super::netsim::chain_capture(Some(hook)) {
            let error = NetDll_XnpEthernetInterceptSetCallbacks(
                XNCALLER_SYSAPP,
                transmit_entry as *const () as usize,
                receive_entry as *const () as usize,
                hook.context,
                0,
            );
            if error != 0 {
                return Err(WsaError(error));
            }
        }
        self.network.netcap.attached = true;
        Ok(())
    }

    fn detach_capture(&mut self) {
        if !super::netsim::chain_capture(None) {
            NetDll_XnpEthernetInterceptSetCallbacks(XNCALLER_SYSAPP, 0, 0, 0, 0);
        }
        self.network.netcap.attached = false;
    }

    fn capture_error(&self) -> Option<Hresult> {
        let error = self.network.netcap.context()?.error.load(Ordering::Acquire);
        (error != 0).then_some(Hresult(error))
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
        let mut recorder = context.accounting.with(|accounting| {
            accounting.recorder.begin_close();
            accounting.recorder
        });
        let result = context.writer.finish(&mut recorder);
        let frames = recorder.frames();
        context.writer.release();
        kernel::ExFreePool(pointer.as_ptr() as usize as u32);
        CaptureClose { result, frames }
    }
}
