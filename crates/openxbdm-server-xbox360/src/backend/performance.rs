//! Performance counters, display capture, video encoder access, and the
//! profiling engines. The engines live in submodules; `service` routes the
//! performance and PIX control codes of the monitor dispatcher to them.

mod capture;
mod counters;
pub(crate) mod module_snapshot;
pub(crate) mod pix;
mod pmc;
mod profiler;
pub(crate) mod studio;
pub(crate) mod xtrace;

pub(crate) use counters::memory_statistics;

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use openxbdm_server::commands::filesystem::DriveTable;
use openxbdm_server::commands::performance;
use openxbdm_server::commands::performance::COUNTER_NAME_CAPACITY;
use openxbdm_server::commands::performance::CaptureValue;
use openxbdm_server::commands::performance::CounterEntry;
use openxbdm_server::commands::performance::CounterSample;
use openxbdm_server::commands::performance::CpuProfilerInfo;
use openxbdm_server::commands::performance::DisplayCapture;
use openxbdm_server::commands::performance::DisplayInformation;
use openxbdm_server::commands::performance::EDID_BLOCK_SIZE;
use openxbdm_server::commands::performance::EdidRead;
use openxbdm_server::commands::performance::PixDogma;
use openxbdm_server::commands::performance::TILE_SIZE;
use openxbdm_server::commands::performance::capture::BufferRequest;
use openxbdm_server::commands::performance::capture::CaptureError;
use openxbdm_server::commands::performance::capture::CaptureFlags;
use openxbdm_server::commands::performance::capture::Started;
use openxbdm_server::commands::performance::counters::CounterError;
use openxbdm_server::commands::performance::counters::CounterQuery;
use openxbdm_server::commands::performance::counters::Evaluation;
use openxbdm_server::commands::performance::profiler::ProfilerError;
use openxbdm_server::commands::performance::profiler::ProfilerFlags;
use openxbdm_server::commands::performance::studio::StudioError;
use xbox360::console::hardware_flags;
use xbox360::module::Ordinal;
use xbox360::module::SystemModule;
use xbox360::module::module_handle;
use xbox360::module::resolve_export;
use xbox360::time::TickCount;
use xbox360_sys::mmio::GpuRegisters;
use xbox360_sys::mmio::GpuStatus;
use xbox360_sys::xboxkrnl;
use xbox360_sys::xboxkrnl::AllocationType;
use xbox360_sys::xboxkrnl::NotificationRegistration;
use xbox360_sys::xboxkrnl::SmcCommand;
use xbox360_sys::xboxkrnl::SmcMessage;
use xbox360_sys::xboxkrnl::VdGetCurrentDisplayInformation;
use xbox360_sys::xboxkrnl::VdReadDVERegisterUlong;
use xbox360_sys::xboxkrnl::VdWriteDVERegisterUlong;

use super::Console;
use super::dispatcher::ControlCode;
use crate::kernel;

/// Bytes of an `SmcCommand::I2c` message.
mod i2c {
    /// Byte of the operation and its flags.
    pub(super) const CONTROL: usize = 1;
    /// Byte of the device: [`DEVICE_SELECT`] and the 7-bit bus address.
    pub(super) const DEVICE: usize = 3;
    pub(super) const REGISTER: usize = 6;
    pub(super) const VALUE: usize = 7;
    pub(super) const DEVICE_SELECT: u8 = 0x80;
    /// Bus address of the video encoder registers 0x100 to 0x1ff.
    pub(super) const ENCODER: u8 = 0x39;
    /// Bus address of the video encoder registers 0x200 to 0x2ff.
    pub(super) const ENCODER_HIGH: u8 = 0x3d;
}

xbox360_sys::flags! {
    /// Control byte ([`i2c::CONTROL`]) of an SMC I2C message.
    pub struct I2cControl(u8) {
        /// The transfer is bracketed by bus requests.
        BRACKETED = 0x01,
        /// Write one byte.
        WRITE_BYTE = 0x20,
    }
}

impl I2cControl {
    /// Control value of the bus request before a bracketed write:
    /// [`I2cControl::BRACKETED`] and bit 0x2, whose meaning is unknown; stock
    /// sets it only here.
    const BUS_REQUEST: Self = Self::BRACKETED.union(Self::from_bits_retain(0x2));
    /// Control value of the bus request after a bracketed write:
    /// [`I2cControl::BRACKETED`] and bit 0x4, whose meaning is unknown; stock
    /// sets it only here.
    const BUS_RELEASE: Self = Self::BRACKETED.union(Self::from_bits_retain(0x4));
}

/// Platform state of this domain.
pub struct Data {
    encoder_extended: Option<bool>,
}

impl Data {
    pub const fn new() -> Self {
        Self {
            encoder_extended: None,
        }
    }
}

/// Start the engines during module initialization, after the control
/// dispatcher is published (stock order in 0x91f32628).
pub(crate) fn initialize() {
    counters::initialize();
    capture::initialize();
    pix::initialize();
    // SAFETY: the record is not registered yet. The routine stays loaded
    // until `shut_down` removes the record.
    unsafe {
        TITLE_ENDED.routine.store(
            title_ended_entry as *const () as usize as u32,
            Ordering::Relaxed,
        );
        TITLE_ENDED
            .priority
            .store(TITLE_ENDED_PRIORITY, Ordering::Relaxed);
        xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_ENDED.as_ptr(), true);
    }
}

/// Stop every timer, DPC, thread, and hook that calls into this image;
/// runs before the image unloads.
pub(crate) fn shut_down() {
    // SAFETY: TITLE_ENDED is the static registration added by `initialize`.
    unsafe { xboxkrnl::ExRegisterTitleTerminateNotification(TITLE_ENDED.as_ptr(), false) };
    counters::shut_down();
    capture::shut_down();
    profiler::shut_down();
    pix::shut_down();
    studio::shut_down();
    xtrace::shut_down();
}

/// Performance part of the title terminate notification (stock 0x91f32398).
pub(crate) fn title_terminated() {
    capture::title_terminated();
    profiler::title_terminated();
    counters::title_terminated();
    pmc::title_terminated();
    pix::title_terminated();
}

/// Title terminate registration of stock 0x91f97444, which runs after the
/// main one (0x91f32398).
static TITLE_ENDED: NotificationRegistration = NotificationRegistration::new();
const TITLE_ENDED_PRIORITY: u32 = 0x6d80_0000;

/// Second title terminate routine (stock 0x91f32418): the title's handles
/// are gone with its process.
extern "C" fn title_ended() {
    counters::title_ended();
    pix::title_ended();
    super::hardware::nuicam::title_ended();
}
crate::exports::bridged!(title_ended_entry, title_ended);

/// Monitor control codes of this domain; `None` for other codes.
///
/// # Safety
///
/// `argument` must meet the contract of the service of `code`.
pub(crate) unsafe fn service(code: ControlCode, argument: u32) -> Option<u32> {
    use ControlCode as C;
    // SAFETY: each `unsafe` arm passes `argument` under the caller's
    // contract for `code`, which is the contract of its service.
    Some(match code {
        C::STUDIO_SET_DEVICE_STATUS => unsafe { studio::service_set_device_status(argument) },
        C::PIX_POST_TEXT => unsafe { pix::service_post_text(argument) },
        C::PIX_WRITE_DWORD => pix::service_write_dword(argument),
        C::PIX_UNREGISTER_CONSUMER => unsafe { pix::service_unregister_consumer(argument) },
        C::PIX_REGISTER_CONSUMER => unsafe { pix::service_register_consumer(argument) },
        C::PIX_WRITE_BLOCK => unsafe { pix::service_write_block(argument) },
        C::PIX_FILTER_CONTROL => unsafe { pix::service_filter_control(argument) },
        C::PIX_REGISTER_PERSISTENT_CONSUMER => unsafe {
            pix::service_register_persistent_consumer(argument)
        },
        C::PIX_WRITE_BLOCK_LIST => unsafe { pix::service_write_block_list(argument) },
        C::PIX_DISK_START => unsafe { pix::service_disk_start(argument) },
        C::PIX_DISK_COMPLETE => pix::service_disk_complete(argument),
        C::PIX_FRAME => pix::service_frame(argument),
        C::PIX_REGISTER_CALLBACK => unsafe { pix::service_register_callback(argument) },
        C::PIX_UNREGISTER_CALLBACK => pix::service_unregister_callback(argument),
        C::PIX_THREAD_SLOT => pix::service_thread_slot(argument),
        C::PIX_SET_DISCARD_OUTPUT => pix::service_set_discard_output(argument),
        C::PIX_STATE_FLAGS => pix::service_state_flags(argument),
        C::PIX_FRAME_RECORD => unsafe { pix::service_frame_record(argument) },
        C::PIX_OPEN_FOR_CAPTURE => unsafe { pix::service_open_for_capture(argument) },
        C::PIX_OPEN_FOR_START => unsafe { pix::service_open_for_start(argument) },
        C::PIX_WRITE_CAPTURE_RECORD => unsafe { pix::service_write_capture_record(argument) },
        C::PIX_QUEUE_MESSAGE => unsafe { pix::service_queue_message(argument) },
        C::PIX_ACQUIRE_OWNER => unsafe { pix::service_acquire_owner(argument) },
        C::PIX_RELEASE_OWNER => pix::service_release_owner(argument),
        C::PIX_RESOURCE_BEGIN => unsafe { pix::service_resource_begin(argument) },
        C::PIX_RESOURCE_RECORD => unsafe { pix::service_resource_record(argument) },
        C::PIX_RESOURCE_END => unsafe { pix::service_resource_end(argument) },
        C::PIX_RESOURCE_INFORMATION => unsafe { pix::service_resource_information(argument) },
        C::PIX_TIMING_REQUEST => unsafe { pix::service_timing_request(argument) },
        C::PIX_FRAME_BUFFER => unsafe { pix::service_frame_buffer(argument) },
        C::PIX_CONFIGURE => unsafe { pix::service_configure(argument) },
        C::PIX_SAMPLES => unsafe { pix::service_samples(argument) },
        C::PIX_COMMAND_BUFFERS => unsafe { pix::service_command_buffers(argument) },
        C::PIX_FENCE => unsafe { pix::service_fence(argument) },
        C::PIX_NUICAM_BEGIN => unsafe { pix::service_nuicam_begin(argument) },
        C::PIX_END => pix::service_end(argument),
        C::STUDIO_SET_TEST_MODE => unsafe { studio::service_set_test_mode(argument) },
        C::XTRACE_START => xtrace::service_start(argument),
        C::XTRACE_STOP => xtrace::service_stop(argument),
        C::XTRACE_INSTRUCTION_COUNT => xtrace::service_instruction_count(argument),
        C::XTRACE_REQUEST_STOP => xtrace::service_request_stop(argument),
        _ => return None,
    })
}

/// A 64-bit value as two relaxed words, high word first; the high word is
/// accessed first. A reader that races the writer may see the halves of
/// two values, as in stock.
#[inline(always)]
pub(super) fn load_pair(pair: &[AtomicU32; 2]) -> u64 {
    let high = pair[0].load(Ordering::Relaxed);
    (u64::from(high) << 32) | u64::from(pair[1].load(Ordering::Relaxed))
}

#[inline(always)]
pub(super) fn store_pair(pair: &[AtomicU32; 2], value: u64) {
    pair[0].store((value >> 32) as u32, Ordering::Relaxed);
    pair[1].store(value as u32, Ordering::Relaxed);
}

/// `NtAllocateVirtualMemory` type: commit, reserve, 64 KiB pages.
pub(crate) const COMMIT_RESERVE_LARGE: AllocationType = AllocationType::COMMIT
    .union(AllocationType::RESERVE)
    .union(AllocationType::LARGE_PAGES);

impl Console {
    fn encoder_extended(&mut self) -> bool {
        /// Video encoder identification register; identifications from
        /// 0x10000 have the extended banks.
        const ID_REGISTER: u32 = 0xfe;
        const EXTENDED_ID: u32 = 0x1_0000;
        *self.performance.encoder_extended.get_or_insert_with(|| {
            // SAFETY: reads a video encoder register; no memory is involved.
            let id = unsafe { VdReadDVERegisterUlong(ID_REGISTER) };
            id >= EXTENDED_ID
        })
    }
}

/// Send one SMC I2C message carrying `control`.
fn send_i2c_request(control: I2cControl) {
    let mut message = SmcMessage::new(SmcCommand::I2c);
    let mut reply = SmcMessage::default();
    message.0[i2c::CONTROL] = control.bits();
    // SAFETY: `message` and `reply` are live SMC messages.
    unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
}

impl performance::Backend for Console {
    fn performance_frequency(&mut self) -> u64 {
        kernel::performance_frequency()
    }

    fn next_counter(
        &mut self,
        context: &mut u32,
        name: &mut [u8; COUNTER_NAME_CAPACITY],
    ) -> Result<CounterEntry, CounterError> {
        counters::next(context, name)
    }

    fn query_counter(
        &mut self,
        name: &[u8],
        query: CounterQuery,
        out: &mut CounterSample,
    ) -> Result<Evaluation, CounterError> {
        let handle = counters::open(name)?;
        let result = counters::reference(handle)
            .map_err(CounterError::Kernel)
            .and_then(|mut counter| {
                let result = counters::query(&mut counter, query, out);
                counter.release();
                result
            });
        handle.close();
        result
    }

    fn capture_display(&mut self) -> DisplayCapture {
        /// Longest wait for a pending flip.
        const FLIP_WAIT_MS: u32 = 500;
        let gpu = GpuRegisters::get();
        let flip_pending = || gpu.status().read().contains(GpuStatus::BUSY);
        if flip_pending() {
            let start = TickCount::now().milliseconds();
            while TickCount::now().milliseconds().wrapping_sub(start) <= FLIP_WAIT_MS
                && flip_pending()
            {}
        }
        let front_buffer = gpu.display_primary_surface().read();
        let mut information = xboxkrnl::DisplayInformation::new();
        // SAFETY: `information` is a live display information block.
        unsafe { VdGetCurrentDisplayInformation(information.as_mut_ptr()) };
        // Bits 8 to 10 hold the gamma setting.
        let gamma = (gpu.display_graphics_control().read() >> 8) & 7 != 0;
        DisplayCapture {
            display: DisplayInformation {
                surface_width: information.surface_width,
                colorspace: information.colorspace,
                left: information.left,
                top: information.top,
                right: information.right,
                bottom: information.bottom,
                scaled_width: information.scaled_width,
                scaled_height: information.scaled_height,
            },
            front_buffer,
            gamma,
        }
    }

    unsafe fn read_framebuffer_page(&mut self, address: u32, page: &mut [u8; TILE_SIZE as usize]) {
        // SAFETY: the caller passes a tile of the front buffer the display
        // controller scans out.
        unsafe { xboxkrnl::KeFlushCacheRange(address, TILE_SIZE) };
        // SAFETY: as above.
        let source = unsafe {
            core::slice::from_raw_parts(address as usize as *const u8, TILE_SIZE as usize)
        };
        page.copy_from_slice(source);
        // SAFETY: as above.
        unsafe { xboxkrnl::KeFlushCacheRange(address, TILE_SIZE) };
    }

    fn read_video_encoder(&mut self, register: u32) -> u32 {
        // SAFETY: reads a video encoder register; no memory is involved.
        unsafe { VdReadDVERegisterUlong(register) }
    }

    fn write_video_encoder(&mut self, register: u32, value: u32) {
        // SAFETY: writes a video encoder register; no memory is involved.
        unsafe { VdWriteDVERegisterUlong(register, value) };
    }

    fn video_encoder_extended(&mut self) -> bool {
        self.encoder_extended()
    }

    /// One-byte I2C write to device 0x39 (0x100..0x1ff) or 0x3d
    /// (0x200..0x2ff), as stock 0x91f23f00.
    fn write_video_encoder_extended(&mut self, register: u32, value: u8) {
        /// Extended registers whose writes are bracketed by bus requests.
        const BRACKETED_REGISTERS: core::ops::RangeInclusive<u32> = 0x1d0..=0x1f5;
        let mut message = SmcMessage::new(SmcCommand::I2c);
        let mut reply = SmcMessage::default();
        message.0[i2c::CONTROL] = I2cControl::WRITE_BYTE.bits();
        message.0[i2c::DEVICE] = i2c::DEVICE_SELECT
            | if register > 0x1ff {
                i2c::ENCODER_HIGH
            } else {
                i2c::ENCODER
            };
        message.0[i2c::REGISTER] = register as u8;
        message.0[i2c::VALUE] = value;
        let bracketed = BRACKETED_REGISTERS.contains(&register);
        let bus_requests = hardware_flags().generation().get() != 0;
        if bracketed {
            message.0[i2c::CONTROL] |= I2cControl::BRACKETED.bits();
            if bus_requests {
                send_i2c_request(I2cControl::BUS_REQUEST);
            }
        }
        // SAFETY: `message` and `reply` are live SMC messages.
        unsafe { xboxkrnl::HalSendSMCMessage(&message, &mut reply) };
        if bracketed && bus_requests {
            send_i2c_request(I2cControl::BUS_RELEASE);
        }
        // Byte 1 of the reply is the error code.
        if reply.0[i2c::CONTROL] != 0 {
            pmc::print(
                c"BD: Failed to write I2C bus address %X, error code %u\n",
                &[u64::from(register), u64::from(reply.0[i2c::CONTROL])],
            );
        }
    }

    fn read_gpu_register(&mut self, index: u32) -> u32 {
        // The command accepts indexes up to 0xfffc.
        GpuRegisters::get().register(index as u16).read()
    }

    fn write_gpu_register(&mut self, index: u32, value: u32) {
        // SAFETY: `gpoke` stores any GPU register at the debugger's request,
        // as stock XBDM does; the debugger answers for the effects. Stock
        // issues no `eieio` after the store.
        unsafe {
            GpuRegisters::get()
                .register(index as u16)
                .write_unordered(value)
        }
    }

    fn read_edid(&mut self, block: u8, output: &mut [u8; EDID_BLOCK_SIZE]) -> EdidRead {
        /// Kernel export that reads an EDID block.
        const EDID_EXPORT: Ordinal = Ordinal::new(623).unwrap();
        let Ok(function) = SystemModule::Kernel
            .handle()
            .and_then(|module| resolve_export(module, EDID_EXPORT))
        else {
            return EdidRead::Unsupported;
        };
        // SAFETY: the export takes (block, 128-byte buffer).
        let read = unsafe {
            kernel::call_export(
                function.raw(),
                u32::from(block),
                output.as_mut_ptr() as usize as u32,
                0,
                0,
            )
        };
        if read == 0 {
            EdidRead::Failed
        } else {
            EdidRead::Read
        }
    }

    fn dedicate_studio_socket(&mut self) -> Result<u16, StudioError> {
        studio::dedicate()
    }

    fn capture_start(
        &mut self,
        name: &[u8],
        path: &[u8],
        buffer: BufferRequest,
    ) -> Result<Started, CaptureError> {
        capture::start(name, path, buffer)
    }

    fn fast_cap_present(&mut self) -> bool {
        capture::fast_cap_present()
    }

    fn call_cap_present(&mut self) -> bool {
        capture::call_cap_present()
    }

    fn capture_stop(&mut self, drives: &DriveTable) -> Result<(), CaptureError> {
        capture::stop(self, drives)
    }

    fn capture_set_flags(&mut self, flags: CaptureFlags) {
        capture::set_flags(flags);
    }

    fn capture_status(&mut self) -> Result<(), CaptureError> {
        capture::status()
    }

    fn capture_abort(&mut self) -> Result<(), CaptureError> {
        capture::abort()
    }

    fn cpu_profiler_start(
        &mut self,
        drives: &DriveTable,
        name: &[u8],
        interval: u32,
        flags: ProfilerFlags,
    ) -> Result<(), ProfilerError> {
        let path = drives.translate(self, name);
        let mut executable = [0u8; module_snapshot::PATH_LIMIT + 2];
        let length = drives.object_path_to_drive_path(
            self,
            module_snapshot::ExecutableObjectPath::read().as_bytes(),
            &mut executable,
        );
        profiler::start(
            path.as_ref().map(|path| path.as_bytes()),
            &executable[..length],
            interval,
            flags,
        )
    }

    fn cpu_profiler_stop(&mut self) -> Result<(), ProfilerError> {
        profiler::stop()
    }

    fn cpu_profiler_info(&mut self) -> Result<CpuProfilerInfo, ProfilerError> {
        profiler::info()
    }

    unsafe fn pix_post(&mut self, code: u32, payload: &[u32]) -> bool {
        // SAFETY: the caller upholds the same contract.
        unsafe { pix::backend::post(code, payload) }
    }

    fn pix_status(&mut self, version: u32, flags: u32) -> Option<[u32; 12]> {
        pix::backend::status(version, flags)
    }

    fn pix_frame_statistics(&mut self, frame: u32) -> Option<[u32; 3]> {
        pix::backend::frame_statistics(frame)
    }

    fn pix_frame_number(&mut self) -> i32 {
        pix::backend::frame_number()
    }

    fn pix_signal_event(&mut self, event: u32) {
        pix::backend::signal_event(event);
    }

    fn pix_set_trace(&mut self, enabled: bool) {
        pix::set_trace(enabled);
    }

    fn pix_counter_control(&mut self, group: u32, id: u32, enabled: bool) {
        pix::backend::counter_control(group, id, enabled);
    }

    fn pix_set_capture_value(&mut self, value: CaptureValue, data: u32) {
        pix::backend::set_capture_value(value, data);
    }

    fn pix_set_capture_text(&mut self, text: &[u8]) {
        pix::backend::set_capture_text(text);
    }

    fn pix_set_legacy_protocol(&mut self, legacy: bool) {
        pix::backend::set_legacy_protocol(legacy);
    }

    fn pix_set_gpu_capture(&mut self, enabled: bool) {
        pix::backend::set_gpu_capture(enabled);
    }

    fn pix_dogma(&mut self) -> Option<PixDogma> {
        pix::backend::dogma()
    }

    fn pix_boot_animation_loaded(&mut self) -> bool {
        // SAFETY: only the result is used, not the handle.
        unsafe { module_handle(c"bootanim.xex") }.is_ok()
    }

    fn pix_capture_ready(&mut self) -> bool {
        pix::backend::capture_ready()
    }

    fn pix_trace_snapshot(&mut self) -> u32 {
        pix::backend::trace_snapshot()
    }

    fn pix_trace_read(&mut self, output: &mut [u8]) -> usize {
        pix::backend::trace_read(output)
    }
}
